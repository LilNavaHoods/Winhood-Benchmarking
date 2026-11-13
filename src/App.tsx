/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { Suspense, lazy, useCallback, useEffect, useState } from 'react';
import {
  BookOpen,
  CheckCircle2,
  Cpu,
  Crosshair,
  Database,
  FileText,
  FolderGit2,
  Github,
  LayoutDashboard,
  Monitor,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Play,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Sparkles,
  Sun,
  Server,
  Upload,
  UserCheck,
  Wrench,
  XCircle,
} from 'lucide-react';
import type {
  AuditLogEntry,
  BenchmarkProfileConfig,
  BenchmarkRun,
  Project,
  Software,
  ToolAdapterInfo,
} from './types/benchmark';
import { DashboardModule } from './components/DashboardModule';
import { HeaderQuickSearch } from './components/HeaderQuickSearch';
import { StepByStepJourneyBar, type AppNavSection } from './components/StepByStepJourneyBar';
import { ContextualScreenHelpBanner } from './components/ContextualScreenHelpBanner';
import { AnalysisProgressHeaderBanner } from './components/AnalysisProgressHeaderBanner';
import { WinHoodLogo } from './components/WinHoodLogo';

// Lazy-loaded modules (Seção 11.7 — Otimização do frontend: Code Splitting & Lazy Loading sob demanda)
const ProjectsAndSoftwaresModule = lazy(() =>
  import('./components/ProjectsAndSoftwaresModule').then((m) => ({
    default: m.ProjectsAndSoftwaresModule,
  }))
);
const BenchmarkWizardModule = lazy(() =>
  import('./components/BenchmarkWizardModule').then((m) => ({
    default: m.BenchmarkWizardModule,
  }))
);
const SecurityAssessmentSuiteModule = lazy(() =>
  import('./components/SecurityAssessmentSuiteModule').then((m) => ({
    default: m.SecurityAssessmentSuiteModule,
  }))
);
const FindingsAndDevSecOpsModule = lazy(() =>
  import('./components/FindingsAndDevSecOpsModule').then((m) => ({
    default: m.FindingsAndDevSecOpsModule,
  }))
);
const ArchitectureQaPerfOsModule = lazy(() =>
  import('./components/ArchitectureQaPerfOsModule').then((m) => ({
    default: m.ArchitectureQaPerfOsModule,
  }))
);
const VeracityAdaptersReportsModule = lazy(() =>
  import('./components/VeracityAdaptersReportsModule').then((m) => ({
    default: m.VeracityAdaptersReportsModule,
  }))
);
const ToolsAndIntegrationsModule = lazy(() =>
  import('./components/ToolsAndIntegrationsModule').then((m) => ({
    default: m.ToolsAndIntegrationsModule,
  }))
);
const SonarDockerCloudHubModule = lazy(() =>
  import('./components/SonarDockerCloudHubModule').then((m) => ({
    default: m.SonarDockerCloudHubModule,
  }))
);
const UserGuideModule = lazy(() =>
  import('./components/UserGuideModule').then((m) => ({
    default: m.UserGuideModule,
  }))
);
const ProjectUploadModal = lazy(() =>
  import('./components/ProjectUploadModal').then((m) => ({
    default: m.ProjectUploadModal,
  }))
);
const GitHubSearchModal = lazy(() =>
  import('./components/GitHubSearchModal').then((m) => ({
    default: m.GitHubSearchModal,
  }))
);
const HardwareAndDisplayBenchmarkModule = lazy(() =>
  import('./components/HardwareAndDisplayBenchmarkModule').then((m) => ({
    default: m.HardwareAndDisplayBenchmarkModule,
  }))
);
const MarketResearchAndCompetitorsModule = lazy(() =>
  import('./components/MarketResearchAndCompetitorsModule').then((m) => ({
    default: m.MarketResearchAndCompetitorsModule,
  }))
);
const ReferenceIntelligenceModule = lazy(() =>
  import('./components/ReferenceIntelligenceModule').then((m) => ({
    default: m.ReferenceIntelligenceModule,
  }))
);

type NavSection = AppNavSection;

export default function App() {
  const [activeNav, setActiveNav] = useState<NavSection>('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);
  const [guideChapterId, setGuideChapterId] = useState<string>('quickstart');
  const [darkMode, setDarkMode] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(true);

  const [currentUser, setCurrentUser] = useState<{
    id: string;
    name: string;
    email: string;
    role: 'ADMIN' | 'SECURITY_LEAD' | 'AUDITOR' | 'QA_ENGINEER';
  }>({
    id: 'usr-admin-01',
    name: 'Lohan Silva',
    email: 'admin@winhood.sec',
    role: 'ADMIN',
  });

  const [dashboardData, setDashboardData] = useState<{
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
  } | null>(null);

  const [projects, setProjects] = useState<Project[]>([]);
  const [softwares, setSoftwares] = useState<Software[]>([]);
  const [profiles, setProfiles] = useState<BenchmarkProfileConfig[]>([]);
  const [adapters, setAdapters] = useState<ToolAdapterInfo[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);

  const [isUploadModalOpen, setIsUploadModalOpen] = useState<boolean>(false);
  const [isGitHubModalOpen, setIsGitHubModalOpen] = useState<boolean>(false);

  const [notification, setNotification] = useState<{
    message: string;
    type: 'success' | 'error';
  } | null>(null);

  const notify = useCallback((message: string, type: 'success' | 'error' = 'success') => {
    setNotification({ message, type });
  }, []);

  useEffect(() => {
    if (!notification) return;
    const timer = setTimeout(() => setNotification(null), 5000);
    return () => clearTimeout(timer);
  }, [notification]);

  useEffect(() => {
    const root = document.documentElement;
    if (darkMode) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [darkMode]);

  const [activeRunningRun, setActiveRunningRun] = useState<BenchmarkRun | null>(null);

  // Requisição consolidada única (/api/bootstrap) substituindo chamadas paralelas redundantes
  const fetchAllBackendState = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/bootstrap');
      if (res.ok) {
        const data = await res.json();
        if (data.user) setCurrentUser(data.user);
        if (data.dashboard) {
          setDashboardData(data.dashboard);
          if (data.dashboard.latestRun?.status === 'RUNNING') {
            setActiveRunningRun(data.dashboard.latestRun);
          } else if (activeRunningRun && data.dashboard.latestRun?.status !== 'RUNNING') {
            setActiveRunningRun(null);
          }
        }
        setProjects(data.projects || []);
        setSoftwares(data.softwares || []);
        setProfiles(data.profiles || []);
        setAdapters(data.adapters || []);
        setAuditLogs(data.auditLogs || []);
      }
    } catch {
      notify('Falha ao sincronizar estado com o servidor backend.', 'error');
    } finally {
      setLoading(false);
    }
  }, [notify, activeRunningRun]);

  useEffect(() => {
    fetchAllBackendState();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleRunUpdated = useCallback((updatedRun: BenchmarkRun) => {
    setDashboardData((prev) => {
      if (!prev) return prev;
      const allFindings = updatedRun.findings || [];
      const activeFindings = allFindings.filter(
        (f) => f.validationStatus !== 'ACCEPTED' && f.validationStatus !== 'FALSE_POSITIVE_REVIEWED'
      );
      const vulnerabilitiesCount = activeFindings.filter((f) =>
        ['SAST', 'SCA', 'SECRETS', 'DAST', 'DATABASE'].includes(f.category)
      ).length;
      const codeQualityIssuesCount = activeFindings.filter((f) =>
        ['CODE_QUALITY', 'ARCHITECTURE'].includes(f.category)
      ).length;
      const avgQuality =
        updatedRun.scoreCards.length > 0
          ? Math.round(
              (updatedRun.scoreCards.reduce((acc, s) => acc + s.groupedScores.qualityScore, 0) /
                updatedRun.scoreCards.length) *
                100
            ) / 100
          : prev.kpis.avgQuality;
      return {
        ...prev,
        kpis: {
          ...prev.kpis,
          vulnerabilitiesCount,
          codeQualityIssuesCount,
          avgQuality,
        },
        latestRun: updatedRun,
        historicalRuns: prev.historicalRuns.map((hr) =>
          hr.id === updatedRun.id
            ? {
                ...hr,
                scores: updatedRun.scoreCards.map((sc) => ({
                  softwareId: sc.softwareId,
                  softwareName: sc.softwareName,
                  overallScore: sc.groupedScores.overallScore,
                  securityScore: sc.groupedScores.securityScore,
                  qualityScore: sc.groupedScores.qualityScore,
                })),
              }
            : hr
        ),
      };
    });
  }, []);

  // Polling leve para verificar se há alguma corrida com status RUNNING ativa
  useEffect(() => {
    const checkActiveProgress = async () => {
      try {
        const res = await fetch('/api/benchmark-runs/active-progress');
        if (res.ok) {
          const data = await res.json();
          if (data.hasActiveRunning && data.run) {
            setActiveRunningRun(data.run);
          } else if (activeRunningRun && !data.hasActiveRunning) {
            setActiveRunningRun(null);
            fetchAllBackendState();
          }
        }
      } catch {
        // Ignora erros momentâneos
      }
    };

    void checkActiveProgress();
    const interval = setInterval(() => {
      void checkActiveProgress();
    }, activeRunningRun ? 1200 : 3500);
    return () => clearInterval(interval);
  }, [activeRunningRun, fetchAllBackendState]);

  const handleEmergencyCancelRun = async (runId: string) => {
    try {
      const res = await fetch(`/api/benchmark-runs/${runId}/emergency-stop`, {
        method: 'POST',
      });
      const data = await res.json();
      if (res.ok) {
        notify('Execução de benchmark interrompida e snapshot restaurado.', 'success');
        setActiveRunningRun(null);
        await fetchAllBackendState();
      } else {
        notify(data.error || 'Falha ao interromper execução.', 'error');
      }
    } catch {
      notify('Erro de comunicação ao interromper análise.', 'error');
    }
  };

  const handleSwitchRole = async (
    role: 'ADMIN' | 'SECURITY_LEAD' | 'AUDITOR' | 'QA_ENGINEER'
  ) => {
    try {
      const res = await fetch('/api/auth/switch-role', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role }),
      });
      const data = await res.json();
      if (res.ok && data.user) {
        setCurrentUser(data.user);
        notify(`Perfil RBAC alterado para ${role}.`, 'success');
        await fetchAllBackendState();
      }
    } catch {
      notify('Erro ao alterar perfil RBAC.', 'error');
    }
  };

  const handleSeedRealWorkspace = async () => {
    try {
      const res = await fetch('/api/system/seed-real-workspace', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        notify(data.message || data.error || 'Acesso negado.', 'error');
        return;
      }
      notify(
        'Repositórios reais (VaultCore Internal v2.4.0 vs KeeSafe Open v2.56.0) ingeridos e analisados!',
        'success'
      );
      await fetchAllBackendState();
    } catch {
      notify('Erro ao inicializar workspace real.', 'error');
    }
  };

  const handleResetEmptyWorkspace = async () => {
    try {
      const res = await fetch('/api/system/reset-empty', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        notify(data.message || data.error || 'Acesso negado.', 'error');
        return;
      }
      notify('Estado inicial vazio ativado (0 avaliações no backend).', 'success');
      await fetchAllBackendState();
    } catch {
      notify('Erro ao limpar workspace.', 'error');
    }
  };

  const handleOpenGuideChapter = useCallback((chapterId = 'quickstart') => {
    setGuideChapterId(chapterId);
    setActiveNav('user_guide');
  }, []);

  const navGroups: Array<{
    groupLabel: string;
    items: Array<{
      id: NavSection;
      stepBadge?: string;
      label: string;
      icon: React.ComponentType<{ className?: string }>;
    }>;
  }> = [
    {
      groupLabel: 'Visão Geral & Preparação',
      items: [
        { id: 'dashboard', label: 'Dashboard Central', icon: LayoutDashboard },
        { id: 'projects', stepBadge: '1', label: 'Projetos & Softwares', icon: FolderGit2 },
        { id: 'wizard', stepBadge: '2', label: 'Nova Avaliação (Wizard)', icon: Sliders },
        { id: 'market_discovery', label: 'Pesquisa de Mercado & Concorrentes', icon: Sparkles },
      ],
    },
    {
      groupLabel: 'Qualidade, Segurança & IA',
      items: [
        {
          id: 'sonar_hub',
          stepBadge: '3A',
          label: 'Sonar Hub: Docker & Cloud',
          icon: Server,
        },
        {
          id: 'tools_integrations',
          stepBadge: '3B',
          label: 'Ferramentas e Integrações',
          icon: Wrench,
        },
        {
          id: 'security_suite',
          stepBadge: '4A',
          label: 'Suíte de Segurança & Resiliência',
          icon: Crosshair,
        },
        { id: 'findings', stepBadge: '4B', label: 'Qualidade & DevSecOps', icon: ShieldAlert },
        { id: 'arch_qa_perf', stepBadge: '4C', label: 'Arquitetura, QA & Perf', icon: Cpu },
        {
          id: 'hardware_benchmark',
          stepBadge: '4D',
          label: 'Hardware, GPU & Monitores',
          icon: Monitor,
        },
      ],
    },
    {
      groupLabel: 'Auditoria, Laudos & Manual',
      items: [
        { id: 'veracity', stepBadge: '5', label: 'Veracidade & Adaptadores', icon: ShieldCheck },
        { id: 'reference_intelligence', stepBadge: '5B', label: 'Inteligência & Golden', icon: Database },
        { id: 'reports', stepBadge: '6', label: 'Relatórios & Auditoria', icon: FileText },
        { id: 'user_guide', label: 'Guia de Utilização', icon: BookOpen },
      ],
    },
  ];

  const allNavItems = navGroups.flatMap((g) => g.items);
  const activeNavLabel =
    allNavItems.find((item) => item.id === activeNav)?.label || 'Dashboard Central';

  return (
    <div className="min-h-screen flex flex-col lg:flex-row bg-slate-50 text-slate-900 dark:bg-[#080b10] dark:text-slate-100">
      {/* Sidebar Navigation (WinHood Architecture - Collapsible w-64 / w-16) */}
      <aside
        className={`w-full ${
          sidebarCollapsed ? 'lg:w-16' : 'lg:w-64'
        } shrink-0 border-b lg:border-b-0 lg:border-r border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0c1017] flex flex-col justify-between transition-all duration-200`}
      >
        <div>
          {/* Brand Header */}
          <div
            className={`px-3.5 py-4 border-b border-slate-200 dark:border-slate-800/80 flex items-center ${
              sidebarCollapsed ? 'justify-center' : 'justify-between'
            }`}
          >
            <button
              type="button"
              onClick={() => setActiveNav('dashboard')}
              className="text-left flex items-center gap-2.5 cursor-pointer"
              title="WinHood Analyzer — Ir para o Dashboard Central"
            >
              <WinHoodLogo size={34} className="brand-mark shrink-0" />
              {!sidebarCollapsed && (
                <div className="flex flex-col leading-tight">
                  <span className="text-sm font-bold tracking-tight text-slate-900 dark:text-slate-100 whitespace-nowrap">
                    WinHood Analyzer
                  </span>
                  <span className="text-[10px] font-mono text-[#31d6c4] tracking-wider">
                    SHA-256 VERACITY ENGINE
                  </span>
                </div>
              )}
            </button>

            {!sidebarCollapsed && (
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => setDarkMode((d) => !d)}
                  aria-label={darkMode ? 'Ativar Tema Claro' : 'Ativar Tema Escuro'}
                  className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:border-[#31d6c4] transition-colors cursor-pointer"
                >
                  {darkMode ? (
                    <Sun className="w-4 h-4 text-[#31d6c4]" />
                  ) : (
                    <Moon className="w-4 h-4" />
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => setSidebarCollapsed(true)}
                  aria-label="Recolher menu lateral"
                  title="Recolher menu lateral"
                  className="hidden lg:inline-flex p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-500 hover:text-[#31d6c4] hover:border-[#31d6c4] transition-colors cursor-pointer"
                >
                  <PanelLeftClose className="w-4 h-4" />
                </button>
              </div>
            )}
          </div>

          {sidebarCollapsed && (
            <div className="hidden lg:flex justify-center py-2 border-b border-slate-200 dark:border-slate-800/80">
              <button
                type="button"
                onClick={() => setSidebarCollapsed(false)}
                aria-label="Expandir menu lateral"
                title="Expandir menu lateral"
                className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-400 hover:text-[#31d6c4] hover:border-[#31d6c4] transition-colors cursor-pointer"
              >
                <PanelLeftOpen className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Primary Navigation Links Grouped by Workflow Stage */}
          <nav aria-label="Navegação Principal" className="p-2.5 space-y-4">
            {navGroups.map((group) => (
              <div key={group.groupLabel} className="space-y-1">
                {!sidebarCollapsed && (
                  <div className="px-2.5 text-[11px] font-mono font-bold uppercase tracking-wider text-slate-400 dark:text-slate-400">
                    {group.groupLabel}
                  </div>
                )}
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeNav === item.id;
                  const isGuide = item.id === 'user_guide';
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => setActiveNav(item.id)}
                      title={
                        item.stepBadge ? `[P${item.stepBadge}] ${item.label}` : item.label
                      }
                      className={`w-full flex items-center ${
                        sidebarCollapsed ? 'justify-center px-2 py-2.5' : 'justify-between gap-2 px-3 py-2'
                      } rounded-lg text-xs font-semibold transition-colors whitespace-nowrap cursor-pointer ${
                        isActive
                          ? 'bg-[#31d6c4]/15 text-[#0e9f8e] dark:text-[#31d6c4] border border-[#31d6c4]/40'
                          : isGuide
                            ? 'text-[#0e9f8e] dark:text-[#31d6c4] bg-[#31d6c4]/5 hover:bg-[#31d6c4]/15 border border-[#31d6c4]/20'
                            : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/50 hover:text-slate-900 dark:hover:text-slate-100 border border-transparent'
                      }`}
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <Icon className="w-4 h-4 shrink-0" />
                        {!sidebarCollapsed && <span className="truncate">{item.label}</span>}
                      </div>
                      {!sidebarCollapsed && item.stepBadge && (
                        <span
                          className={`text-[11px] font-mono px-1.5 py-0.5 rounded shrink-0 ${
                            isActive
                              ? 'bg-[#31d6c4] text-slate-950 font-bold'
                              : 'bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400'
                          }`}
                        >
                          P{item.stepBadge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            ))}
          </nav>
        </div>

        {/* User Status in Sidebar Footer (Acesso Completo ADMIN por Padrão) */}
        {!sidebarCollapsed && (
          <div className="p-4 border-t border-slate-200 dark:border-slate-800/80 space-y-1.5 text-xs">
            <div className="flex items-center gap-2 text-slate-700 dark:text-slate-300 font-semibold">
              <UserCheck className="w-4 h-4 text-[#31d6c4] shrink-0" />
              <span className="truncate">{currentUser.name}</span>
            </div>
            <div className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-600 dark:text-[#31d6c4]">
              <span className="w-1.5 h-1.5 rounded-full bg-[#31d6c4]" />
              <span>Acesso Total Irrestrito (ADMIN)</span>
            </div>
          </div>
        )}
      </aside>

      {/* Main Content Shell */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Bar Contract (SaaS Dashboard Breadcrumb + Quick Search + Actions) */}
        <header className="flex items-center justify-between gap-3 px-6 py-3 border-b border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0c1017]">
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500 dark:text-slate-400 whitespace-nowrap shrink-0">
            <span className="hidden sm:inline">WinHood Platform</span>
            <span className="hidden sm:inline">/</span>
            <span className="text-slate-900 dark:text-slate-100 font-semibold">
              {activeNavLabel}
            </span>
          </div>

          {/* Quick Search for Projects, Softwares, and Runs */}
          <HeaderQuickSearch
            projects={projects}
            softwares={softwares}
            historicalRuns={dashboardData?.historicalRuns}
            onSelectProject={(_id) => setActiveNav('projects')}
            onSelectSoftware={(_id) => setActiveNav('projects')}
            onSelectRun={(_id) => setActiveNav('security_suite')}
            onOpenUpload={() => setIsUploadModalOpen(true)}
            onOpenGitHub={() => setIsGitHubModalOpen(true)}
            onOpenWizard={() => setActiveNav('wizard')}
          />

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => handleOpenGuideChapter('quickstart')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#31d6c4]/10 text-[#0e9f8e] dark:text-[#31d6c4] border border-[#31d6c4]/30 hover:bg-[#31d6c4]/20 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              title="Abrir Guia Completo de Utilização"
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span className="hidden xl:inline">Guia de Utilização</span>
            </button>

            <button
              type="button"
              onClick={() => setIsUploadModalOpen(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700 hover:border-[#31d6c4] hover:text-[#31d6c4] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              title="Fazer upload de projeto ou pasta de código"
            >
              <Upload className="w-3.5 h-3.5 text-[#31d6c4]" />
              <span className="hidden md:inline">Upload</span>
            </button>

            <button
              type="button"
              onClick={() => setIsGitHubModalOpen(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700 hover:border-indigo-400 hover:text-indigo-400 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              title="Pesquisar e importar projetos do GitHub"
            >
              <Github className="w-3.5 h-3.5 text-indigo-400" />
              <span className="hidden md:inline">GitHub</span>
            </button>

            {/* Static Production Environment Indicator (Especificação 4 — 100% PRODUÇÃO) */}
            <div className="hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-[11px] font-mono font-bold text-emerald-600 dark:text-[#31d6c4] shrink-0">
              <span className="w-1.5 h-1.5 rounded-full bg-[#31d6c4]" />
              <span>PRODUÇÃO (Zero Fakes)</span>
            </div>

            <button
              type="button"
              onClick={() => setActiveNav('wizard')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" />
              <span className="hidden lg:inline">Nova Avaliação</span>
            </button>
          </div>
        </header>

        {/* Componente Visual de Progresso de Análise (Barra Global com ETA e Status em Andamento) */}
        <AnalysisProgressHeaderBanner
          activeRun={activeRunningRun}
          onCancelRun={handleEmergencyCancelRun}
          onRefresh={fetchAllBackendState}
        />

        {/* Visual Numbered Step-by-Step Journey Bar */}
        <StepByStepJourneyBar
          activeNav={activeNav}
          softwaresCount={softwares.length}
          hasEvaluations={Boolean(dashboardData?.hasEvaluations)}
          findingsCount={dashboardData?.latestRun?.findings.length || 0}
          evidenceCount={dashboardData?.latestRun?.evidenceChain.length || 0}
          onNavigate={(tab) => setActiveNav(tab)}
          onSeedRealWorkspace={handleSeedRealWorkspace}
          onOpenGuide={handleOpenGuideChapter}
        />

        {/* Notification Banner */}
        {notification && (
          <div
            role="status"
            className={`px-6 py-2.5 text-xs font-semibold flex items-center justify-between border-b ${
              notification.type === 'error'
                ? 'bg-rose-500/15 text-rose-600 dark:text-rose-300 border-rose-500/30'
                : 'bg-[#31d6c4]/15 text-emerald-800 dark:text-[#31d6c4] border-[#31d6c4]/30'
            }`}
          >
            <div className="flex items-center gap-2">
              {notification.type === 'error' ? (
                <XCircle className="w-4 h-4 shrink-0" />
              ) : (
                <CheckCircle2 className="w-4 h-4 shrink-0" />
              )}
              <span>{notification.message}</span>
            </div>
            <button
              type="button"
              onClick={() => setNotification(null)}
              className="text-xs underline ml-4 cursor-pointer"
            >
              Fechar
            </button>
          </div>
        )}

        {/* Active Module Viewport (Lazy-Loaded via Suspense) */}
        <main className="flex-1 p-6 lg:p-8 max-w-[1440px] w-full mx-auto">
          {/* Contextual Help Banner for the Active Screen */}
          <ContextualScreenHelpBanner
            activeNav={activeNav}
            onOpenGuideChapter={handleOpenGuideChapter}
          />

          <Suspense
            fallback={
              <div className="h-64 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] animate-pulse p-6 text-xs text-slate-500 font-mono">
                Carregando módulo sob demanda...
              </div>
            }
          >
            {activeNav === 'dashboard' && (
              <DashboardModule
                data={dashboardData}
                loading={loading}
                onNavigate={(tab) => setActiveNav(tab as NavSection)}
                onSeedRealWorkspace={handleSeedRealWorkspace}
                onResetEmptyWorkspace={handleResetEmptyWorkspace}
              />
            )}

            {activeNav === 'projects' && (
              <ProjectsAndSoftwaresModule
                projects={projects}
                softwares={softwares}
                onRefresh={fetchAllBackendState}
                onNotify={notify}
                onOpenUpload={() => setIsUploadModalOpen(true)}
                onOpenGitHub={() => setIsGitHubModalOpen(true)}
              />
            )}

            {activeNav === 'wizard' && (
              <BenchmarkWizardModule
                projects={projects}
                softwares={softwares}
                profiles={profiles}
                onRequestUpload={() => setIsUploadModalOpen(true)}
                onRunCompleted={async () => {
                  await fetchAllBackendState();
                  setActiveNav('dashboard');
                }}
                onNotify={notify}
              />
            )}

            {activeNav === 'market_discovery' && (
              <MarketResearchAndCompetitorsModule
                projects={projects}
                softwares={softwares}
                selectedProjectId={projects[0]?.id || ''}
                onRefreshWorkspace={fetchAllBackendState}
                onNavigate={(tab) => setActiveNav(tab as NavSection)}
                onNotify={notify}
              />
            )}

            {activeNav === 'sonar_hub' && (
              <SonarDockerCloudHubModule onNotify={notify} />
            )}

            {activeNav === 'tools_integrations' && (
              <ToolsAndIntegrationsModule
                softwares={softwares}
                onNotify={notify}
              />
            )}

            {activeNav === 'security_suite' && (
              <SecurityAssessmentSuiteModule
                latestRun={dashboardData?.latestRun || null}
                onRefresh={fetchAllBackendState}
                onNotify={notify}
              />
            )}

            {activeNav === 'findings' && (
              <FindingsAndDevSecOpsModule
                latestRun={dashboardData?.latestRun || null}
                onRunUpdated={handleRunUpdated}
                onNotify={notify}
              />
            )}

            {activeNav === 'arch_qa_perf' && (
              <ArchitectureQaPerfOsModule latestRun={dashboardData?.latestRun || null} />
            )}

            {activeNav === 'hardware_benchmark' && (
              <HardwareAndDisplayBenchmarkModule
                runs={dashboardData?.latestRun ? [dashboardData.latestRun] : []}
                selectedRunId={dashboardData?.latestRun?.id}
                onRefreshData={() => {
                  void fetchAllBackendState();
                }}
              />
            )}

            {activeNav === 'veracity' && (
              <VeracityAdaptersReportsModule
                key="veracity-tab"
                latestRun={dashboardData?.latestRun || null}
                adapters={adapters}
                auditLogs={auditLogs}
                initialTab="veracity"
              />
            )}

            {activeNav === 'reference_intelligence' && (
              <ReferenceIntelligenceModule
                latestRun={dashboardData?.latestRun || null}
                softwares={softwares}
                onNotify={notify}
              />
            )}

            {activeNav === 'reports' && (
              <VeracityAdaptersReportsModule
                key="reports-tab"
                latestRun={dashboardData?.latestRun || null}
                adapters={adapters}
                auditLogs={auditLogs}
                initialTab="reports"
              />
            )}

            {activeNav === 'user_guide' && (
              <UserGuideModule
                initialChapterId={guideChapterId}
                hasEvaluations={Boolean(dashboardData?.hasEvaluations)}
                softwaresCount={softwares.length}
                onNavigate={(tab) => setActiveNav(tab)}
                onSeedRealWorkspace={handleSeedRealWorkspace}
                onOpenUploadModal={() => setIsUploadModalOpen(true)}
                onOpenGitHubModal={() => setIsGitHubModalOpen(true)}
                onNotify={notify}
              />
            )}
          </Suspense>
        </main>
      </div>

      {/* Lazy-Loaded Modals */}
      {isUploadModalOpen && (
        <Suspense fallback={null}>
          <ProjectUploadModal
            isOpen={isUploadModalOpen}
            onClose={() => setIsUploadModalOpen(false)}
            onSuccess={fetchAllBackendState}
            onNotify={notify}
          />
        </Suspense>
      )}

      {isGitHubModalOpen && (
        <Suspense fallback={null}>
          <GitHubSearchModal
            isOpen={isGitHubModalOpen}
            projects={projects}
            onClose={() => setIsGitHubModalOpen(false)}
            onSuccess={fetchAllBackendState}
            onNotify={notify}
          />
        </Suspense>
      )}
    </div>
  );
}
