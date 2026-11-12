import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ArrowRight,
  Award,
  CheckCircle2,
  ExternalLink,
  Filter,
  Globe,
  Layers,
  Lock,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldCheck,
  Sliders,
  Sparkles,
  Unlock,
} from 'lucide-react';
import type { MarketCompetitorCandidate, Project, Software } from '../types/benchmark';
import { WinHoodLogo } from './WinHoodLogo';

interface MarketResearchAndCompetitorsModuleProps {
  projects: Project[];
  softwares: Software[];
  selectedProjectId: string;
  onRefreshWorkspace: () => Promise<void>;
  onNavigate: (tab: string) => void;
  onNotify: (msg: string, type?: 'success' | 'error') => void;
}

interface SimilarityWeights {
  purpose: number;
  features: number;
  audience: number;
  platform: number;
  distribution: number;
  integrations: number;
}

const DEFAULT_SIMILARITY_WEIGHTS: SimilarityWeights = {
  purpose: 30,
  features: 25,
  audience: 15,
  platform: 10,
  distribution: 10,
  integrations: 10,
};

const FALLBACK_MARKET_CATEGORIES: string[] = [
  'Password & Secrets Management',
  'Application Security & SAST/SCA',
  'Relational & Embedded Databases',
  'API Gateways & Microservices',
  'Observability & APM Telemetry',
  'Identity & Access Management (IAM/SSO)',
  'CI/CD & DevSecOps Pipelines',
  'Container & Kubernetes Security',
  'Cloud Infrastructure & IaC',
  'Web Frameworks & Runtime Engines',
  'Enterprise ERP & Financial Core',
  'Messaging & Event Streaming',
  'AI/LLM Code Review & Engineering Agents',
  'Backup, Disaster Recovery & Storage',
  'Static Site & Documentation Engines',
  'Endpoint Protection & EDR',
];

export const MarketResearchAndCompetitorsModule: React.FC<
  MarketResearchAndCompetitorsModuleProps
> = ({
  projects,
  softwares,
  selectedProjectId,
  onRefreshWorkspace,
  onNavigate,
  onNotify,
}) => {
  const nonCompetitorSoftwares = useMemo(
    () => softwares.filter((s) => !s.isMarketCompetitor),
    [softwares]
  );

  const [discoveryMode, setDiscoveryMode] = useState<'BASE_SOFTWARE' | 'FREE_CATEGORY'>(
    nonCompetitorSoftwares.length > 0 ? 'BASE_SOFTWARE' : 'FREE_CATEGORY'
  );
  const [selectedSoftwareId, setSelectedSoftwareId] = useState<string>(
    nonCompetitorSoftwares[0]?.id || ''
  );
  const [selectedCategory, setSelectedCategory] = useState<string>(
    'Password & Secrets Management'
  );
  const [purposeSearch, setPurposeSearch] = useState<string>('');
  const [targetProjectId, setTargetProjectId] = useState<string>(
    selectedProjectId || projects[0]?.id || ''
  );
  const [weights, setWeights] = useState<SimilarityWeights>({
    ...DEFAULT_SIMILARITY_WEIGHTS,
  });

  const [availableCategories, setAvailableCategories] = useState<string[]>(
    FALLBACK_MARKET_CATEGORIES
  );
  const [catalogSize, setCatalogSize] = useState<number>(38);
  const [candidates, setCandidates] = useState<MarketCompetitorCandidate[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [approvingId, setApprovingId] = useState<string | null>(null);
  const [homologatedIds, setHomologatedIds] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!selectedSoftwareId && nonCompetitorSoftwares[0]?.id) {
      setSelectedSoftwareId(nonCompetitorSoftwares[0].id);
    }
  }, [nonCompetitorSoftwares, selectedSoftwareId]);

  useEffect(() => {
    if (!targetProjectId && (selectedProjectId || projects[0]?.id)) {
      setTargetProjectId(selectedProjectId || projects[0]?.id || '');
    }
  }, [projects, selectedProjectId, targetProjectId]);

  const runMarketDiscovery = useCallback(async () => {
    setLoading(true);
    try {
      const payload =
        discoveryMode === 'BASE_SOFTWARE' && selectedSoftwareId
          ? {
              softwareId: selectedSoftwareId,
              purpose: purposeSearch.trim() || undefined,
            }
          : {
              category: selectedCategory,
              purpose: purposeSearch.trim() || selectedCategory,
            };

      const res = await fetch('/api/market/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errData = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(errData.error || `Erro HTTP ${res.status}`);
      }

      const data = (await res.json()) as {
        category?: string;
        catalogSize?: number;
        categories?: string[];
        candidates?: MarketCompetitorCandidate[];
      };

      if (Array.isArray(data.categories) && data.categories.length > 0) {
        setAvailableCategories(data.categories);
      }
      if (typeof data.catalogSize === 'number') {
        setCatalogSize(data.catalogSize);
      }
      setCandidates(Array.isArray(data.candidates) ? data.candidates : []);
    } catch (err: any) {
      onNotify(
        err?.message || 'Falha ao consultar o Motor de Descoberta de Concorrentes.',
        'error'
      );
    } finally {
      setLoading(false);
    }
  }, [discoveryMode, onNotify, purposeSearch, selectedCategory, selectedSoftwareId]);

  useEffect(() => {
    void runMarketDiscovery();
  }, [runMarketDiscovery]);

  const totalWeightsSum =
    weights.purpose +
    weights.features +
    weights.audience +
    weights.platform +
    weights.distribution +
    weights.integrations;

  const rankedCandidates = useMemo(() => {
    const safeSum = totalWeightsSum > 0 ? totalWeightsSum : 100;
    return candidates
      .map((cand) => {
        const b = cand.similarityBreakdown || {
          purpose: cand.similarityScore,
          features: cand.similarityScore,
          audience: 85,
          platform: 90,
          distribution: 85,
          integrations: 80,
        };
        const weightedScore = Math.round(
          (b.purpose * weights.purpose +
            b.features * weights.features +
            b.audience * weights.audience +
            b.platform * weights.platform +
            b.distribution * weights.distribution +
            b.integrations * weights.integrations) /
            safeSum
        );
        return {
          ...cand,
          computedMatchScore: Math.max(0, Math.min(100, weightedScore)),
          effectiveBreakdown: b,
        };
      })
      .sort((a, b) => b.computedMatchScore - a.computedMatchScore);
  }, [candidates, totalWeightsSum, weights]);

  const handleWeightChange = (key: keyof SimilarityWeights, value: number) => {
    setWeights((prev) => ({
      ...prev,
      [key]: Math.max(0, Math.min(100, value)),
    }));
  };

  const handleResetWeights = () => {
    setWeights({ ...DEFAULT_SIMILARITY_WEIGHTS });
    onNotify('Pesos de similaridade restaurados para o padrão oficial (30/25/15/10/10/10).');
  };

  const handleApproveAndImport = async (
    candidate: MarketCompetitorCandidate,
    openWizardAfter: boolean
  ) => {
    const effectiveProjectId = targetProjectId || projects[0]?.id;
    const effectiveMainSoftwareId =
      selectedSoftwareId || nonCompetitorSoftwares[0]?.id || softwares[0]?.id;

    if (!effectiveProjectId || !effectiveMainSoftwareId) {
      onNotify(
        'Cadastre ou selecione ao menos 1 Projeto e 1 Software Base antes de homologar um concorrente para comparação.',
        'error'
      );
      return;
    }

    setApprovingId(candidate.id);
    try {
      const res = await fetch('/api/market/approve-and-compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: effectiveProjectId,
          mainSoftwareId: effectiveMainSoftwareId,
          competitorCandidate: candidate,
        }),
      });
      const data = (await res.json()) as { error?: string; message?: string };
      if (!res.ok) {
        throw new Error(data.error || 'Falha ao homologar concorrente de mercado.');
      }

      setHomologatedIds((prev) => {
        const next = new Set(prev);
        next.add(candidate.id);
        return next;
      });

      await onRefreshWorkspace();
      onNotify(
        data.message ||
          `Concorrente "${candidate.name}" homologado e importado para o projeto com sucesso!`
      );

      if (openWizardAfter) {
        onNavigate('wizard');
      }
    } catch (err: any) {
      onNotify(err?.message || 'Erro ao homologar concorrente.', 'error');
    } finally {
      setApprovingId(null);
    }
  };

  const activeBaseSoftware = nonCompetitorSoftwares.find(
    (s) => s.id === selectedSoftwareId
  );

  return (
    <div className="space-y-6">
      {/* Header Principal */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-start gap-4">
            <WinHoodLogo size={48} className="shrink-0" />
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-semibold bg-[#31d6c4]/15 text-[#31d6c4] border border-[#31d6c4]/30">
                  MARKET INTELLIGENCE ENGINE
                </span>
                <span className="px-2.5 py-0.5 rounded text-[11px] font-mono bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                  {catalogSize} Softwares Reais Verificados · {availableCategories.length} Categorias
                </span>
              </div>
              <h1 className="text-xl sm:text-2xl font-bold text-slate-900 dark:text-slate-100 mt-1.5">
                Pesquisa de Mercado &amp; Descoberta de Concorrentes Equivalentes
              </h1>
              <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mt-1">
                Descubra concorrentes reais de mercado (Open-Source ou Closed-Source), calibre os 6 eixos matemáticos de similaridade e homologue candidatos para comparação técnica imparcial.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => void runMarketDiscovery()}
              disabled={loading}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Atualizar Descoberta
            </button>
            <button
              type="button"
              onClick={() => onNavigate('wizard')}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
            >
              Ir para Nova Avaliação (Wizard)
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Bloco 1 & 2: Seletor de Software Base / Busca Livre + Painel de Pesos de Similaridade Multi-Critério */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
        {/* Coluna Esquerda (7 cols): Seletor de Software Base ou Busca Livre por Categoria */}
        <div className="xl:col-span-7 rounded-xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-5 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3.5">
            <div className="flex items-center gap-2">
              <Search className="w-4 h-4 text-[#31d6c4]" />
              <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                1. Critério de Descoberta (Software Base ou Busca Livre em 16 Categorias)
              </h2>
            </div>

            <div className="inline-flex rounded-lg border border-slate-200 dark:border-slate-800 p-0.5 bg-slate-100 dark:bg-[#080b10]">
              <button
                type="button"
                onClick={() => setDiscoveryMode('BASE_SOFTWARE')}
                className={`px-3 py-1 rounded-md text-xs font-semibold transition-colors cursor-pointer ${
                  discoveryMode === 'BASE_SOFTWARE'
                    ? 'bg-[#31d6c4] text-slate-950'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                Por Software Cadastrado
              </button>
              <button
                type="button"
                onClick={() => setDiscoveryMode('FREE_CATEGORY')}
                className={`px-3 py-1 rounded-md text-xs font-semibold transition-colors cursor-pointer ${
                  discoveryMode === 'FREE_CATEGORY'
                    ? 'bg-[#31d6c4] text-slate-950'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                Busca Livre por Categoria
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {discoveryMode === 'BASE_SOFTWARE' ? (
              <div>
                <label
                  htmlFor="market-base-software-select"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5"
                >
                  Software Base Cadastrado no Inventário
                </label>
                <select
                  id="market-base-software-select"
                  value={selectedSoftwareId}
                  onChange={(e) => setSelectedSoftwareId(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#31d6c4]"
                >
                  {nonCompetitorSoftwares.length === 0 ? (
                    <option value="">Nenhum software cadastrado — use Busca Livre</option>
                  ) : (
                    nonCompetitorSoftwares.map((sw) => (
                      <option key={sw.id} value={sw.id}>
                        {sw.name} (v{sw.version}) — {sw.category || 'Multi-Domínio'}
                      </option>
                    ))
                  )}
                </select>
              </div>
            ) : (
              <div>
                <label
                  htmlFor="market-category-select"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5"
                >
                  Categoria Oficial de Mercado ({availableCategories.length} domínios)
                </label>
                <select
                  id="market-category-select"
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#31d6c4]"
                >
                  {availableCategories.map((cat) => (
                    <option key={cat} value={cat}>
                      {cat}
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div>
              <label
                htmlFor="market-target-project-select"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5"
              >
                Projeto de Destino para Homologação
              </label>
              <select
                id="market-target-project-select"
                value={targetProjectId}
                onChange={(e) => setTargetProjectId(e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#31d6c4]"
              >
                {projects.length === 0 ? (
                  <option value="">Nenhum projeto cadastrado</option>
                ) : (
                  projects.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))
                )}
              </select>
            </div>
          </div>

          <div>
            <label
              htmlFor="market-purpose-input"
              className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5"
            >
              Filtro de Propósito, Palavra-Chave ou Stack Tecnológica (Opcional)
            </label>
            <div className="flex gap-2">
              <input
                id="market-purpose-input"
                type="text"
                value={purposeSearch}
                onChange={(e) => setPurposeSearch(e.target.value)}
                placeholder="Ex.: KDBX, AES-256-GCM, SAST, SonarQube, SQLite, Zero-Knowledge, OIDC..."
                className="flex-1 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#31d6c4]"
              />
              <button
                type="button"
                onClick={() => void runMarketDiscovery()}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-900 dark:bg-slate-800 text-white hover:bg-slate-800 dark:hover:bg-slate-700 transition-colors cursor-pointer shrink-0"
              >
                Filtrar Catálogo
              </button>
            </div>
          </div>

          {discoveryMode === 'BASE_SOFTWARE' && activeBaseSoftware && (
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#0b0f17] p-3.5 text-xs space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-900 dark:text-slate-100">
                  Software Base Ativo: {activeBaseSoftware.name} (v{activeBaseSoftware.version})
                </span>
                <span className="font-mono text-[11px] text-[#31d6c4]">
                  SHA-256: {activeBaseSoftware.packageSha256.slice(0, 12)}...
                </span>
              </div>
              <p className="text-slate-600 dark:text-slate-400">
                {activeBaseSoftware.description}
              </p>
              <div className="flex flex-wrap gap-1.5 pt-1">
                <span className="px-2 py-0.5 rounded bg-slate-200/70 dark:bg-slate-800 text-[11px] font-mono text-slate-700 dark:text-slate-300">
                  Categoria: {activeBaseSoftware.category}
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-200/70 dark:bg-slate-800 text-[11px] font-mono text-slate-700 dark:text-slate-300">
                  Arquitetura: {activeBaseSoftware.architecture}
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-200/70 dark:bg-slate-800 text-[11px] font-mono text-slate-700 dark:text-slate-300">
                  SO: {activeBaseSoftware.operatingSystem}
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Coluna Direita (5 cols): Painel de Pesos de Similaridade Multi-Critério (6 Eixos — 100%) */}
        <div className="xl:col-span-5 rounded-xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3.5">
            <div className="flex items-center gap-2">
              <Sliders className="w-4 h-4 text-[#31d6c4]" />
              <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                2. Pesos de Similaridade (6 Eixos)
              </h2>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                  totalWeightsSum === 100
                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                    : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                }`}
              >
                Soma: {totalWeightsSum}%
              </span>
              <button
                type="button"
                onClick={handleResetWeights}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
                title="Restaurar Pesos Oficiais (30/25/15/10/10/10)"
              >
                <RotateCcw className="w-3 h-3" />
                Padrão
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            {(
              [
                {
                  key: 'purpose',
                  id: 'sim-weight-purpose',
                  label: 'Propósito Funcional',
                  defaultPct: 30,
                },
                {
                  key: 'features',
                  id: 'sim-weight-features',
                  label: 'Funcionalidades',
                  defaultPct: 25,
                },
                {
                  key: 'audience',
                  id: 'sim-weight-audience',
                  label: 'Público-Alvo',
                  defaultPct: 15,
                },
                {
                  key: 'platform',
                  id: 'sim-weight-platform',
                  label: 'Plataforma / SO',
                  defaultPct: 10,
                },
                {
                  key: 'distribution',
                  id: 'sim-weight-distribution',
                  label: 'Modelo de Distribuição',
                  defaultPct: 10,
                },
                {
                  key: 'integrations',
                  id: 'sim-weight-integrations',
                  label: 'Integrações & APIs',
                  defaultPct: 10,
                },
              ] as const
            ).map((axis) => (
              <div
                key={axis.key}
                className="rounded-lg border border-slate-200 dark:border-slate-800/90 bg-slate-50/60 dark:bg-[#080b10] p-2.5"
              >
                <div className="flex items-center justify-between text-xs mb-1">
                  <label
                    htmlFor={axis.id}
                    className="font-semibold text-slate-700 dark:text-slate-300"
                  >
                    {axis.label}
                  </label>
                  <span className="font-mono font-bold text-[#31d6c4]">
                    {weights[axis.key]}%{' '}
                    <span className="text-[10px] text-slate-500 font-normal">
                      (ref {axis.defaultPct}%)
                    </span>
                  </span>
                </div>
                <input
                  id={axis.id}
                  type="range"
                  min={0}
                  max={100}
                  step={5}
                  value={weights[axis.key]}
                  onChange={(e) =>
                    handleWeightChange(axis.key, Number.parseInt(e.target.value, 10))
                  }
                  className="w-full accent-[#31d6c4] cursor-pointer"
                />
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bloco 3: Matriz Comparativa de Concorrentes Descobertos */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-6 space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <Award className="w-5 h-5 text-[#31d6c4]" />
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                3. Matriz Comparativa de Concorrentes Descobertos ({rankedCandidates.length})
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Ordenados dinamicamente pelo Score de Similaridade Ponderado. Nenhum concorrente entra no benchmark sem aprovação humana explícita.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Open-Source: {rankedCandidates.filter((c) => c.openSource).length}
            </span>
            <span className="px-2.5 py-1 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              Closed-Source (Docs): {rankedCandidates.filter((c) => !c.openSource).length}
            </span>
          </div>
        </div>

        {rankedCandidates.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-300 dark:border-slate-800 p-8 text-center">
            <Filter className="w-8 h-8 text-slate-400 mx-auto mb-2" />
            <p className="text-sm font-semibold text-slate-700 dark:text-slate-300">
              Nenhum concorrente encontrado para os filtros informados.
            </p>
            <p className="text-xs text-slate-500 mt-1">
              Experimente limpar o filtro de palavra-chave ou alternar para outra categoria de mercado.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {rankedCandidates.map((cand) => {
              const isAlreadyInInventory =
                homologatedIds.has(cand.id) ||
                softwares.some((s) => s.id === `sw-competitor-${cand.id}`);

              return (
                <div
                  key={cand.id}
                  className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-[#090d14] p-5 flex flex-col justify-between gap-4 hover:border-[#31d6c4]/50 transition-colors"
                >
                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                            {cand.name}
                          </h3>
                          {cand.version && (
                            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                              v{cand.version}
                            </span>
                          )}
                          {cand.openSource ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                              <Unlock className="w-3 h-3" />
                              OPEN-SOURCE (Full Source)
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
                              <Lock className="w-3 h-3" />
                              CLOSED-SOURCE (Public Docs)
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                          Fornecedor: <strong className="text-slate-700 dark:text-slate-300">{cand.vendor}</strong> · Categoria: {cand.category}
                        </p>
                      </div>

                      <div className="text-right shrink-0">
                        <div className="px-3 py-1 rounded-lg bg-[#31d6c4]/15 border border-[#31d6c4]/40 text-[#31d6c4] font-mono font-bold text-sm">
                          {cand.computedMatchScore}% Match
                        </div>
                        <div className="text-[10px] font-mono text-slate-500 mt-0.5">
                          Confiança: {cand.confidence || 'HIGH'}
                        </div>
                      </div>
                    </div>

                    <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                      {cand.description}
                    </p>

                    {/* Barras dos 6 Eixos de Similaridade */}
                    <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 pt-1">
                      {(
                        [
                          { label: 'Propósito', val: cand.effectiveBreakdown.purpose },
                          { label: 'Features', val: cand.effectiveBreakdown.features },
                          { label: 'Público', val: cand.effectiveBreakdown.audience },
                          { label: 'Plataforma', val: cand.effectiveBreakdown.platform },
                          { label: 'Distrib.', val: cand.effectiveBreakdown.distribution },
                          { label: 'Integr.', val: cand.effectiveBreakdown.integrations },
                        ] as const
                      ).map((item) => (
                        <div
                          key={item.label}
                          className="rounded border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0f141c] p-1.5 text-center"
                        >
                          <div className="text-[10px] text-slate-500 dark:text-slate-400 truncate">
                            {item.label}
                          </div>
                          <div className="text-xs font-mono font-bold text-slate-900 dark:text-slate-100">
                            {item.val}%
                          </div>
                        </div>
                      ))}
                    </div>

                    {/* Funcionalidades Equivalentes vs Distintas */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
                      <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-2.5">
                        <div className="font-semibold text-emerald-400 text-[11px] mb-1 flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Funcionalidades Equivalentes
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {(cand.equivalentFeatures || cand.featuresIdentified || [])
                            .slice(0, 4)
                            .map((feat) => (
                              <span
                                key={feat}
                                className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 text-[10px] font-mono"
                              >
                                {feat}
                              </span>
                            ))}
                        </div>
                      </div>

                      <div className="rounded-lg border border-indigo-500/20 bg-indigo-500/5 p-2.5">
                        <div className="font-semibold text-indigo-400 text-[11px] mb-1 flex items-center gap-1">
                          <Sparkles className="w-3.5 h-3.5" />
                          Diferenciais / Distinções
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {(cand.distinctFeatures && cand.distinctFeatures.length > 0
                            ? cand.distinctFeatures
                            : ['Arquitetura Própria', 'Ecossistema Dedicado']
                          )
                            .slice(0, 3)
                            .map((feat) => (
                              <span
                                key={feat}
                                className="px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-300 text-[10px] font-mono"
                              >
                                {feat}
                              </span>
                            ))}
                        </div>
                      </div>
                    </div>

                    {/* Links Oficiais Verificáveis */}
                    <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono pt-1">
                      {cand.officialUrl && (
                        <a
                          href={cand.officialUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-[#31d6c4] hover:underline"
                        >
                          <Globe className="w-3 h-3" />
                          Site Oficial
                          <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      )}
                      {cand.documentationUrl && (
                        <a
                          href={cand.documentationUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-slate-600 dark:text-slate-400 hover:text-[#31d6c4] hover:underline"
                        >
                          <Layers className="w-3 h-3" />
                          Documentação Técnica
                          <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      )}
                      {(cand.repositoryUrl || cand.publicRepoUrl) && (
                        <a
                          href={cand.repositoryUrl || cand.publicRepoUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-slate-600 dark:text-slate-400 hover:text-[#31d6c4] hover:underline"
                        >
                          <ShieldCheck className="w-3 h-3" />
                          Repositório Público
                          <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      )}
                    </div>
                  </div>

                  {/* Rodapé de Homologação e Importação */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-slate-200 dark:border-slate-800/80">
                    {isAlreadyInInventory ? (
                      <span className="inline-flex items-center gap-1.5 text-xs font-mono font-semibold text-emerald-400">
                        <CheckCircle2 className="w-4 h-4" />
                        Concorrente Homologado no Inventário
                      </span>
                    ) : (
                      <span className="text-[11px] text-slate-500">
                        Requer aprovação humana para comparação
                      </span>
                    )}

                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        disabled={approvingId === cand.id}
                        onClick={() => void handleApproveAndImport(cand, false)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-[#31d6c4]/50 text-[#31d6c4] hover:bg-[#31d6c4]/10 transition-colors cursor-pointer disabled:opacity-50"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        {approvingId === cand.id
                          ? 'Homologando...'
                          : 'Homologar Concorrente e Importar para o Projeto'}
                      </button>

                      <button
                        type="button"
                        disabled={approvingId === cand.id}
                        onClick={() => void handleApproveAndImport(cand, true)}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-50"
                      >
                        Homologar &amp; Comparar Agora
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
