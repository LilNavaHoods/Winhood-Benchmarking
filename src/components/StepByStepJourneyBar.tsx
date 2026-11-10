import React from 'react';
import {
  ArrowRight,
  BookOpen,
  CheckCircle2,
  CircleDot,
  Cpu,
  FileText,
  FolderGit2,
  Play,
  ShieldCheck,
  Sliders,
  Wrench,
} from 'lucide-react';

export type AppNavSection =
  | 'dashboard'
  | 'projects'
  | 'wizard'
  | 'market_discovery'
  | 'sonar_hub'
  | 'tools_integrations'
  | 'security_suite'
  | 'findings'
  | 'arch_qa_perf'
  | 'veracity'
  | 'reports'
  | 'user_guide';

interface StepByStepJourneyBarProps {
  activeNav: AppNavSection;
  softwaresCount: number;
  hasEvaluations: boolean;
  findingsCount: number;
  evidenceCount: number;
  onNavigate: (tab: AppNavSection) => void;
  onSeedRealWorkspace: () => Promise<void>;
  onOpenGuide: (chapterId?: string) => void;
}

export const StepByStepJourneyBar: React.FC<StepByStepJourneyBarProps> = ({
  activeNav,
  softwaresCount,
  hasEvaluations,
  findingsCount,
  evidenceCount,
  onNavigate,
  onSeedRealWorkspace,
  onOpenGuide,
}) => {
  const step1Done = softwaresCount >= 2;
  const step2Done = hasEvaluations;
  const step3Done = hasEvaluations && softwaresCount >= 2;
  const step4Done = hasEvaluations && findingsCount > 0;
  const step5Done = hasEvaluations && evidenceCount > 0;
  const step6Done = hasEvaluations;

  // Determinar qual é o próximo passo recomendado na jornada
  const recommendedStepNumber = !step1Done
    ? 1
    : !step2Done
      ? 2
      : activeNav === 'dashboard'
        ? 3
        : activeNav === 'tools_integrations'
          ? 4
          : activeNav === 'security_suite' || activeNav === 'findings' || activeNav === 'arch_qa_perf'
            ? 5
            : 6;

  const steps: Array<{
    stepNumber: number;
    title: string;
    subtitle: string;
    targetNav: AppNavSection;
    relatedNavs: AppNavSection[];
    completed: boolean;
    icon: React.ComponentType<{ className?: string }>;
    badgeText: string;
  }> = [
    {
      stepNumber: 1,
      title: '1. Cadastrar Softwares A & B',
      subtitle:
        softwaresCount >= 2
          ? `${softwaresCount} softwares prontos para análise`
          : 'Importe via Upload, GitHub ou Par Real',
      targetNav: 'projects',
      relatedNavs: ['projects'],
      completed: step1Done,
      icon: FolderGit2,
      badgeText: step1Done ? `${softwaresCount} registrados` : 'Pendente',
    },
    {
      stepNumber: 2,
      title: '2. Configurar & Rodar Benchmark',
      subtitle: step2Done
        ? 'Pesos 100% validados e notas geradas'
        : 'Defina pesos (soma 100%) e execute',
      targetNav: 'wizard',
      relatedNavs: ['wizard'],
      completed: step2Done,
      icon: Sliders,
      badgeText: step2Done ? 'Executado' : 'Ação Principal',
    },
    {
      stepNumber: 3,
      title: '3. SonarQube & Docker Hub',
      subtitle: 'Docker Oficial, SonarCloud, Scanner CLI e Hardware Multi-Core',
      targetNav: 'sonar_hub',
      relatedNavs: ['sonar_hub', 'tools_integrations'],
      completed: step3Done,
      icon: Wrench,
      badgeText: 'Qualidade & Docker',
    },
    {
      stepNumber: 4,
      title: '4. Segurança, QA & Arquitetura',
      subtitle:
        findingsCount > 0
          ? `${findingsCount} achados técnicos mapeados`
          : 'Superfície de ataque, SAST e performance',
      targetNav: 'security_suite',
      relatedNavs: ['security_suite', 'findings', 'arch_qa_perf'],
      completed: step4Done,
      icon: Cpu,
      badgeText: findingsCount > 0 ? `${findingsCount} achados` : 'Inspeção',
    },
    {
      stepNumber: 5,
      title: '5. Veracidade & Evidências',
      subtitle:
        evidenceCount > 0
          ? `${evidenceCount} hashes SHA-256 auditáveis`
          : 'Validação sem dados simulados',
      targetNav: 'veracity',
      relatedNavs: ['veracity'],
      completed: step5Done,
      icon: ShieldCheck,
      badgeText: evidenceCount > 0 ? `${evidenceCount} provas` : 'Auditoria',
    },
    {
      stepNumber: 6,
      title: '6. Laudo & Decisão A/B',
      subtitle: step6Done
        ? 'Vencedor técnico definido e exportável'
        : 'Exporte JSON, Markdown ou HTML/PDF',
      targetNav: 'reports',
      relatedNavs: ['reports', 'dashboard'],
      completed: step6Done,
      icon: FileText,
      badgeText: step6Done ? 'Pronto' : 'Laudo Final',
    },
  ];

  return (
    <section
      aria-label="Jornada Passo a Passo da Análise"
      className="border-b border-slate-200 dark:border-slate-800/80 bg-slate-100/70 dark:bg-[#0a0e15] px-6 py-3"
    >
      <div className="max-w-[1440px] mx-auto space-y-2.5">
        {/* Top status row */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs">
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-[#31d6c4]/15 text-[#0e9f8e] dark:text-[#31d6c4] font-mono font-semibold border border-[#31d6c4]/30">
              <CircleDot className="w-3 h-3" />
              JORNADA GUIADA (6 PASSOS)
            </span>
            <span className="text-slate-600 dark:text-slate-400">
              {!step1Done
                ? 'Comece pelo Passo 1 cadastrando pelo menos dois softwares (ou carregue o exemplo real com 1 clique).'
                : !step2Done
                  ? 'Softwares prontos! Avance para o Passo 2 para configurar os pesos matemáticos e rodar a comparação A/B.'
                  : 'Avaliação A/B concluída! Navegue pelos Passos 3 a 6 para auditar SonarQube, Segurança, Veracidade e exportar o Laudo.'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            {!step1Done && (
              <button
                type="button"
                onClick={onSeedRealWorkspace}
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
              >
                <Play className="w-3 h-3" />
                Carregar Exemplo Real A/B (1 Clique)
              </button>
            )}
            <button
              type="button"
              onClick={() => onOpenGuide('quickstart')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] text-slate-700 dark:text-slate-200 hover:border-[#31d6c4] hover:text-[#0e9f8e] dark:hover:text-[#31d6c4] transition-colors cursor-pointer"
            >
              <BookOpen className="w-3.5 h-3.5 text-[#31d6c4]" />
              <span>Abrir Guia Completo de Utilização</span>
            </button>
          </div>
        </div>

        {/* 6 Interactive Numbered Steps */}
        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
          {steps.map((step) => {
            const isCurrentScreen = step.relatedNavs.includes(activeNav);
            const isRecommended = step.stepNumber === recommendedStepNumber && !isCurrentScreen;

            return (
              <button
                key={step.stepNumber}
                type="button"
                onClick={() => onNavigate(step.targetNav)}
                className={`group text-left rounded-lg border px-3 py-2 transition-all cursor-pointer flex flex-col justify-between ${
                  isCurrentScreen
                    ? 'bg-white dark:bg-[#111823] border-[#31d6c4] ring-1 ring-[#31d6c4]/30'
                    : isRecommended
                      ? 'bg-white/90 dark:bg-[#0f1520] border-amber-500/60 hover:border-[#31d6c4]'
                      : 'bg-white/60 dark:bg-[#0c1017] border-slate-200 dark:border-slate-800/80 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between gap-1.5">
                  <span
                    className={`inline-flex items-center gap-1 text-[11px] font-mono font-bold ${
                      isCurrentScreen
                        ? 'text-[#0e9f8e] dark:text-[#31d6c4]'
                        : step.completed
                          ? 'text-emerald-600 dark:text-emerald-400'
                          : isRecommended
                            ? 'text-amber-600 dark:text-amber-400'
                            : 'text-slate-500 dark:text-slate-400'
                    }`}
                  >
                    {step.completed ? (
                      <CheckCircle2 className="w-3.5 h-3.5 shrink-0 text-emerald-500" />
                    ) : (
                      <span className="w-4 h-4 rounded-full bg-slate-200 dark:bg-slate-800 text-[10px] flex items-center justify-center">
                        {step.stepNumber}
                      </span>
                    )}
                    <span className="truncate">{step.badgeText}</span>
                  </span>

                  {isRecommended && (
                    <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-600 dark:text-amber-300 border border-amber-500/30">
                      Próximo
                    </span>
                  )}
                  {isCurrentScreen && (
                    <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-[#31d6c4]/15 text-[#0e9f8e] dark:text-[#31d6c4]">
                      Tela Atual
                    </span>
                  )}
                </div>

                <div className="mt-1.5">
                  <div className="text-xs font-bold text-slate-900 dark:text-slate-100 group-hover:text-[#0e9f8e] dark:group-hover:text-[#31d6c4] transition-colors flex items-center justify-between gap-1">
                    <span className="truncate">{step.title}</span>
                    <ArrowRight className="w-3 h-3 shrink-0 opacity-60 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                  <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate mt-0.5">
                    {step.subtitle}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
};
