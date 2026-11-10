import React, { useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Play,
  Scale,
  ShieldCheck,
  Sliders,
} from 'lucide-react';
import type {
  BenchmarkCategoryKey,
  BenchmarkProfileConfig,
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
}

export const BenchmarkWizardModule: React.FC<BenchmarkWizardModuleProps> = ({
  projects,
  softwares,
  profiles,
  onRunCompleted,
  onNotify,
}) => {
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [selectedProjectId, setSelectedProjectId] = useState(projects[0]?.id || '');
  const [selectedSoftwareIds, setSelectedSoftwareIds] = useState<string[]>(
    softwares.slice(0, 2).map((s) => s.id)
  );
  const [selectedProfileId, setSelectedProfileId] = useState(
    profiles[0]?.id || 'prof-complete-enterprise'
  );
  const [weights, setWeights] = useState<Record<BenchmarkCategoryKey, number>>({
    ...(profiles[0]?.weights || DEFAULT_CATEGORY_WEIGHTS),
  });
  const [enablePenaltyCaps, setEnablePenaltyCaps] = useState(true);
  const [cpuCoresLimit, setCpuCoresLimit] = useState(4);
  const [memoryMbLimit, setMemoryMbLimit] = useState(4096);
  const [osTarget, setOsTarget] = useState(
    'Windows 11 Enterprise Sandbox / Linux Worker 6.8'
  );
  const [workloadConcurrency, setWorkloadConcurrency] = useState(100);
  const [dastFormalAuth, setDastFormalAuth] = useState(true);
  const [authorizedByOwner, setAuthorizedByOwner] = useState(
    'CISO & Architecture Board (Auth #WH-2026-884)'
  );
  const [executing, setExecuting] = useState(false);

  const projectSoftwares = softwares.filter(
    (s) => !selectedProjectId || s.projectId === selectedProjectId
  );

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

  const handleToggleSoftware = (id: string) => {
    setSelectedSoftwareIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleNormalizeWeightsTo100 = () => {
    setWeights({ ...DEFAULT_CATEGORY_WEIGHTS });
  };

  const handleExecuteBenchmark = async () => {
    if (selectedSoftwareIds.length < 1) {
      onNotify('Selecione pelo menos 1 software para avaliação.', 'error');
      return;
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
          softwareIds: selectedSoftwareIds,
          profileName: activeProf?.name || 'Perfil Customizado WinHood',
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
        }),
      });
      const payload = await res.json();
      if (!res.ok) {
        onNotify(payload.message || payload.error || 'Falha ao executar benchmark.', 'error');
        setExecuting(false);
        return;
      }
      if (payload.run.status === 'RUNNING') {
        onNotify(
          `Benchmark "${payload.run.id}" em andamento! Acompanhe o progresso e ETA no cabeçalho.`,
          'success'
        );
      } else {
        onNotify(
          `Benchmark "${payload.run.id}" concluído e validado pelo Motor de Veracidade!`,
          'success'
        );
      }
      await onRunCompleted();
    } catch {
      onNotify('Erro de comunicação ao orquestrar benchmark.', 'error');
    } finally {
      setExecuting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
          Assistente Guiado de Configuração &amp; Execução de Benchmark
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          Configure participantes, pesos matemáticos por categoria, travas de segurança e equivalência experimental antes de iniciar os workers.
        </p>
      </div>

      {/* Wizard Step Indicator Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
        {[
          { num: 1, title: '01. Projeto & Softwares', sub: 'Seleção de 2+ participantes' },
          { num: 2, title: '02. Perfis & Pesos (100%)', sub: 'Validação matemática e travas' },
          { num: 3, title: '03. Equivalência & DAST', sub: 'Hardware, SO e autorização' },
          { num: 4, title: '04. Execução & Veracidade', sub: 'Disparo de adaptadores reais' },
        ].map((item) => {
          const active = step === item.num;
          const done = step > item.num;
          return (
            <button
              key={item.num}
              type="button"
              onClick={() => setStep(item.num as 1 | 2 | 3 | 4)}
              className={`text-left p-4 rounded-lg border transition-colors cursor-pointer ${
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
              <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">
                {item.sub}
              </div>
            </button>
          );
        })}
      </div>

      {/* Step Content Container */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-6 space-y-6">
        {step === 1 && (
          <div className="space-y-6">
            <div>
              <label
                htmlFor="wiz-project"
                className="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-2"
              >
                1. Selecione o Projeto de Benchmarking
              </label>
              <select
                id="wiz-project"
                value={selectedProjectId || projects[0]?.id || ''}
                onChange={(e) => setSelectedProjectId(e.target.value)}
                className="w-full max-w-xl rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3.5 py-2.5 text-xs text-slate-900 dark:text-slate-100"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.category})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold text-slate-700 dark:text-slate-300">
                  2. Selecione dois ou mais Softwares Participantes (Selecionados:{' '}
                  <span className="font-mono tabular-nums text-[#31d6c4]">
                    {selectedSoftwareIds.length}
                  </span>
                  )
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {(projectSoftwares.length > 0 ? projectSoftwares : softwares).map(
                  (sw, idx) => {
                    const checked = selectedSoftwareIds.includes(sw.id);
                    return (
                      <label
                        key={sw.id}
                        className={`flex items-start gap-3 p-4 rounded-lg border cursor-pointer transition-colors ${
                          checked
                            ? 'border-[#31d6c4] bg-[#31d6c4]/5'
                            : 'border-slate-200 dark:border-slate-800'
                        }`}
                      >
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => handleToggleSoftware(sw.id)}
                          className="mt-1 accent-[#31d6c4]"
                        />
                        <div className="space-y-1 text-xs">
                          <div className="font-bold text-slate-900 dark:text-slate-100">
                            Software {String.fromCharCode(65 + idx)}: {sw.name} (v{sw.version})
                          </div>
                          <div className="text-slate-500 dark:text-slate-400">
                            {sw.vendor} · {sw.architecture}
                          </div>
                          <div className="font-mono tabular-nums text-[11px] text-slate-500">
                            SHA-256: {sw.packageSha256.slice(0, 20)}... · {sw.inventory.totalFiles} arqs ({sw.inventory.totalLinesOfCode} LOC)
                          </div>
                        </div>
                      </label>
                    );
                  }
                )}
              </div>

              {selectedSoftwareIds.length === 0 && (
                <p className="text-xs text-rose-500 mt-3 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4" />
                  Selecione pelo menos 1 software para executar a análise e avaliação.
                </p>
              )}
              {selectedSoftwareIds.length === 1 && (
                <p className="text-xs text-[#31d6c4] mt-3 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-[#31d6c4]" />
                  1 software selecionado: Modo de Avaliação Individual de Qualidade, Segurança e Métricas SonarQube.
                </p>
              )}
              {selectedSoftwareIds.length >= 2 && (
                <p className="text-xs text-emerald-400 mt-3 flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  {selectedSoftwareIds.length} softwares selecionados: Modo Benchmark Comparativo e Ranking Determinístico.
                </p>
              )}
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
              <div>
                <label
                  htmlFor="wiz-profile"
                  className="block text-xs font-bold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Perfil Reutilizável de Benchmark
                </label>
                <select
                  id="wiz-profile"
                  value={selectedProfileId}
                  onChange={(e) => handleSelectProfile(e.target.value)}
                  className="rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
                >
                  {profiles.map((prof) => (
                    <option key={prof.id} value={prof.id}>
                      {prof.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-center gap-3">
                <div
                  className={`px-3.5 py-2 rounded-lg border text-xs font-mono tabular-nums font-bold ${
                    weightValidation.valid
                      ? 'border-emerald-500/40 text-emerald-600 dark:text-[#31d6c4]'
                      : 'border-rose-500/50 text-rose-500'
                  }`}
                >
                  Soma Matemática: {weightValidation.totalWeight}% / 100%
                </div>
                <button
                  type="button"
                  onClick={handleNormalizeWeightsTo100}
                  className="px-3 py-2 rounded-lg text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
                >
                  Restaurar Padrão (100%)
                </button>
              </div>
            </div>

            {!weightValidation.valid && (
              <div className="p-3.5 rounded-lg border border-rose-500/40 bg-rose-500/10 text-xs text-rose-600 dark:text-rose-400 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{weightValidation.errors.join(' ')}</span>
              </div>
            )}

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
              {(Object.keys(CATEGORY_LABELS) as BenchmarkCategoryKey[]).map((key) => (
                <div
                  key={key}
                  className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-[#080b10]"
                >
                  <label
                    htmlFor={`weight-${key}`}
                    className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5"
                  >
                    {CATEGORY_LABELS[key]}
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      id={`weight-${key}`}
                      type="number"
                      min={0}
                      max={100}
                      value={weights[key]}
                      onChange={(e) =>
                        setWeights((prev) => ({
                          ...prev,
                          [key]: Number(e.target.value),
                        }))
                      }
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-2.5 py-1.5 text-xs font-mono tabular-nums text-slate-900 dark:text-slate-100"
                    />
                    <span className="text-xs font-mono text-slate-400">%</span>
                  </div>
                </div>
              ))}
            </div>

            <div className="pt-4 border-t border-slate-200 dark:border-slate-800">
              <label className="flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={enablePenaltyCaps}
                  onChange={(e) => setEnablePenaltyCaps(e.target.checked)}
                  className="mt-1 accent-[#31d6c4]"
                />
                <div className="text-xs">
                  <div className="font-bold text-slate-900 dark:text-slate-100">
                    Habilitar Travas Matemáticas Rigorosas (Penalty Caps / Kill Switches)
                  </div>
                  <div className="text-slate-500 dark:text-slate-400 mt-0.5">
                    Impede que uma média elevada esconda falhas críticas (ex: vulnerabilidade crítica validada ou segredo exposto limita a nota de segurança a 2.00 e a nota geral a 2.90).
                  </div>
                </div>
              </label>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-6">
            <div className="flex items-center gap-2 text-sm font-bold text-slate-900 dark:text-slate-100">
              <Cpu className="w-4 h-4 text-[#31d6c4]" />
              <span>Condições Experimentais de Equivalência &amp; Segurança dos Workers</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label
                  htmlFor="eq-cpu"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Limite de vCPUs por Worker
                </label>
                <input
                  id="eq-cpu"
                  type="number"
                  value={cpuCoresLimit}
                  onChange={(e) => setCpuCoresLimit(Number(e.target.value))}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs font-mono tabular-nums"
                />
              </div>
              <div>
                <label
                  htmlFor="eq-ram"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Limite de Memória RAM (MB)
                </label>
                <input
                  id="eq-ram"
                  type="number"
                  value={memoryMbLimit}
                  onChange={(e) => setMemoryMbLimit(Number(e.target.value))}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs font-mono tabular-nums"
                />
              </div>
              <div>
                <label
                  htmlFor="eq-vus"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Concorrência Controlada (VUs)
                </label>
                <input
                  id="eq-vus"
                  type="number"
                  value={workloadConcurrency}
                  onChange={(e) => setWorkloadConcurrency(Number(e.target.value))}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs font-mono tabular-nums"
                />
              </div>
              <div>
                <label
                  htmlFor="eq-os"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Ambiente Isolado (MicroVM / Sandbox)
                </label>
                <input
                  id="eq-os"
                  type="text"
                  value={osTarget}
                  onChange={(e) => setOsTarget(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs"
                />
              </div>
            </div>

            {!eqValidation.equivalent && (
              <div className="p-3.5 rounded-lg border border-rose-500/40 bg-rose-500/10 text-xs text-rose-600 dark:text-rose-400">
                <strong>Bloqueio de Equivalência Experimental:</strong>{' '}
                {eqValidation.reasons.join(' ')}
              </div>
            )}

            <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-3">
              <label className="flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={dastFormalAuth}
                  onChange={(e) => setDastFormalAuth(e.target.checked)}
                  className="mt-1 accent-[#31d6c4]"
                />
                <div className="text-xs">
                  <div className="font-bold text-slate-900 dark:text-slate-100">
                    Autorização Formal do Proprietário para Verificações Ativas (DAST / Sandbox)
                  </div>
                  <div className="text-slate-500 dark:text-slate-400">
                    Testes dinâmicos nunca são disparados contra ambientes de terceiros sem termo formal registrado.
                  </div>
                </div>
              </label>
              <div>
                <label
                  htmlFor="eq-auth-owner"
                  className="block text-[11px] font-semibold text-slate-500 mb-1"
                >
                  Identificação do Termo de Autorização Formal
                </label>
                <input
                  id="eq-auth-owner"
                  type="text"
                  value={authorizedByOwner}
                  onChange={(e) => setAuthorizedByOwner(e.target.value)}
                  className="w-full max-w-lg rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-3 py-1.5 text-xs font-mono"
                />
              </div>
            </div>
          </div>
        )}

        {step === 4 && (
          <div className="space-y-6">
            <div className="flex items-center gap-2 text-base font-bold text-slate-900 dark:text-slate-100">
              <ShieldCheck className="w-5 h-5 text-[#31d6c4]" />
              <span>Revisão Final do Contrato de Execução e Veracidade</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono tabular-nums">
              <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                <div className="text-slate-400 font-sans">Softwares Selecionados</div>
                <div className="text-base font-bold text-slate-900 dark:text-slate-100 mt-1">
                  {selectedSoftwareIds.length} participantes
                </div>
                <div className="text-slate-500 mt-1 font-sans">
                  {softwares
                    .filter((s) => selectedSoftwareIds.includes(s.id))
                    .map((s) => `${s.name} (v${s.version})`)
                    .join(' vs ')}
                </div>
              </div>

              <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                <div className="text-slate-400 font-sans">Validação Matemática de Pesos</div>
                <div className="text-base font-bold text-emerald-600 dark:text-[#31d6c4] mt-1">
                  {weightValidation.totalWeight}% ({weightValidation.valid ? 'VÁLIDO' : 'INVÁLIDO'})
                </div>
                <div className="text-slate-500 mt-1 font-sans">
                  Travas Penalty Caps: {enablePenaltyCaps ? 'ATIVAS' : 'DESATIVADAS'}
                </div>
              </div>

              <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                <div className="text-slate-400 font-sans">Equivalência Experimental</div>
                <div className="text-base font-bold text-slate-900 dark:text-slate-100 mt-1">
                  {cpuCoresLimit} vCPUs · {memoryMbLimit} MB RAM
                </div>
                <div className="text-slate-500 mt-1 font-sans">
                  Status: {eqValidation.equivalent ? 'EQUIVALENTE' : 'BLOQUEADO'}
                </div>
              </div>
            </div>

            <div className="pt-2">
              <button
                type="button"
                disabled={
                  executing ||
                  selectedSoftwareIds.length < 1 ||
                  !weightValidation.valid ||
                  !eqValidation.equivalent
                }
                onClick={handleExecuteBenchmark}
                className="inline-flex items-center gap-2 px-6 py-3 rounded-lg text-sm font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] disabled:opacity-50 transition-colors cursor-pointer"
              >
                <Play className="w-4 h-4" />
                {executing
                  ? 'Executando Adaptadores e Validando Evidências SHA-256...'
                  : selectedSoftwareIds.length === 1
                    ? 'Executar Avaliação Completa de Qualidade & SonarQube'
                    : 'Executar Benchmark Comparativo Real'}
              </button>
            </div>
          </div>
        )}

        {/* Wizard Footer Navigation */}
        <div className="flex items-center justify-between pt-4 border-t border-slate-200 dark:border-slate-800">
          <button
            type="button"
            disabled={step === 1}
            onClick={() => setStep((s) => Math.max(1, s - 1) as 1 | 2 | 3 | 4)}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 disabled:opacity-40 cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Etapa Anterior
          </button>

          {step < 4 && (
            <button
              type="button"
              onClick={() => setStep((s) => Math.min(4, s + 1) as 1 | 2 | 3 | 4)}
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
