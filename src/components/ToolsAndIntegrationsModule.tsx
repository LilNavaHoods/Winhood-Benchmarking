import React, { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cloud,
  Code2,
  Cpu,
  Database,
  GitBranch,
  GitPullRequest,
  HardDrive,
  Lock,
  Play,
  Power,
  RefreshCw,
  Server,
  ShieldCheck,
  Sliders,
  Terminal,
  Wrench,
  XCircle,
} from 'lucide-react';
import type {
  GitProviderType,
  IntegrationTestStepResult,
  ResourceOptimizationReport,
  Software,
  SonarABComparisonResult,
  SonarAndToolsDatabaseBundle,
  SonarInstanceRecord,
} from '../types/benchmark';

interface ToolsAndIntegrationsModuleProps {
  softwares: Software[];
  onNotify: (message: string, type?: 'success' | 'error') => void;
}

type SubView =
  | 'cards'
  | 'ab_comparison'
  | 'ai_remediation'
  | 'integration_tests'
  | 'optimization';

export const ToolsAndIntegrationsModule: React.FC<ToolsAndIntegrationsModuleProps> = ({
  softwares,
  onNotify,
}) => {
  const [subView, setSubView] = useState<SubView>('cards');
  const [loading, setLoading] = useState<boolean>(true);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  const [toolsDb, setToolsDb] = useState<SonarAndToolsDatabaseBundle | null>(null);
  const [hostResources, setHostResources] = useState<{
    ramTotalMb: number;
    ramAvailableMb: number;
    cpuCores: number;
    diskFreeGb: number;
    operatingSystem: string;
    kernelRelease: string;
    isGvisorSandbox: boolean;
    javaAvailable: boolean;
    javaVersion: string | null;
    vmMaxMapCount: number;
    meetsSonarQubeLocalRequirements: boolean;
    blockingReasons: string[];
    recommendations: string[];
  } | null>(null);

  const [lifecycleStatus, setLifecycleStatus] = useState<{
    localServerRunning: boolean;
    activeAnalysesCount: number;
    queuedTasksCount: number;
  }>({
    localServerRunning: false,
    activeAnalysesCount: 0,
    queuedTasksCount: 0,
  });

  const [cacheStats, setCacheStats] = useState<{
    entriesCount: number;
    totalHits: number;
    sizeKb: number;
  }>({ entriesCount: 0, totalHits: 0, sizeKb: 0 });

  // Form states for SonarQube Local & Remote
  const [localPort, setLocalPort] = useState<number>(9000);
  const [localToken, setLocalToken] = useState<string>('');
  const [remoteUrl, setRemoteUrl] = useState<string>('');
  const [remoteName, setRemoteName] = useState<string>('SonarQube Community Build Remoto');
  const [remoteToken, setRemoteToken] = useState<string>('');

  // Form state for SonarQube Cloud
  const [cloudOrg, setCloudOrg] = useState<string>('');
  const [cloudToken, setCloudToken] = useState<string>('');
  const [cloudConsent, setCloudConsent] = useState<boolean>(false);

  // Form state for VS Code Connected Mode
  const [vscodeMode, setVscodeMode] = useState<'COMMUNITY_BUILD' | 'SERVER' | 'CLOUD'>('COMMUNITY_BUILD');
  const [vscodeServerUrl, setVscodeServerUrl] = useState<string>('http://localhost:9000');
  const [vscodeConsent, setVscodeConsent] = useState<boolean>(false);

  // Form state for Gitar AI
  const [gitarProvider, setGitarProvider] = useState<GitProviderType>('GITHUB');
  const [gitarApiUrl, setGitarApiUrl] = useState<string>('https://api.gitar.ai/v1');
  const [gitarToken, setGitarToken] = useState<string>('');
  const [gitarRepos, setGitarRepos] = useState<string>(
    'corp-sec/vaultcore-internal, open-sec/keesafe-kdbx'
  );
  const [gitarConsent, setGitarConsent] = useState<boolean>(false);

  // Selected tool for External SARIF import
  const [selectedSarifTool, setSelectedSarifTool] = useState<string>('semgrep');
  const [selectedSarifSoftwareId, setSelectedSarifSoftwareId] = useState<string>(
    softwares[0]?.id || ''
  );

  // Lifecycle limits state
  const [maxConcurrency, setMaxConcurrency] = useState<number>(1);
  const [idleMinutes, setIdleMinutes] = useState<number>(15);

  const fetchToolsData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/tools-integrations');
      if (res.ok) {
        const data = await res.json();
        setToolsDb(data.toolsDb);
        setHostResources(data.hostResources);
        setLifecycleStatus(data.lifecycleStatus);
        setCacheStats(data.cacheStats);
        if (data.lifecycleLimits) {
          setMaxConcurrency(data.lifecycleLimits.maxConcurrentSonarAnalyses || 1);
          setIdleMinutes(data.lifecycleLimits.idleShutdownMinutes || 15);
        }
        const remoteInst = (data.toolsDb?.sonar_instances || []).find(
          (i: SonarInstanceRecord) => i.mode === 'REMOTE'
        );
        if (remoteInst && remoteInst.serverUrl) {
          setRemoteUrl(remoteInst.serverUrl);
        }
        const cloudInst = (data.toolsDb?.sonar_instances || []).find(
          (i: SonarInstanceRecord) => i.mode === 'CLOUD'
        );
        if (cloudInst && cloudInst.organizationKey) {
          setCloudOrg(cloudInst.organizationKey);
        }
      }
    } catch {
      onNotify('Erro ao carregar estado de Ferramentas e Integrações.', 'error');
    } finally {
      setLoading(false);
    }
  }, [onNotify]);

  useEffect(() => {
    fetchToolsData();
  }, [fetchToolsData]);

  const handleProbeInstance = async (params: {
    instanceId: string;
    serverUrl: string;
    port: number;
    token: string;
    mode: 'LOCAL' | 'REMOTE' | 'CLOUD';
    organizationKey?: string;
    name?: string;
  }) => {
    if (params.mode === 'CLOUD' && !cloudConsent) {
      onNotify(
        'Para conectar ao SonarQube Cloud (SaaS externo), marque a autorização explícita de envio de metadados.',
        'error'
      );
      return;
    }
    setBusyAction(`probe-${params.instanceId}`);
    try {
      const res = await fetch('/api/sonarqube/probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      });
      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || data.message || 'Erro ao verificar instância.', 'error');
        return;
      }
      const st = data.instance?.connectionState;
      if (st === 'READY' || st === 'CONNECTED') {
        onNotify(
          `Conexão verificada (${st}): SonarQube v${data.instance.version} respondeu com sucesso!`,
          'success'
        );
      } else {
        onNotify(
          `Estado verificado via probeSonarQube(): ${st} — ${data.instance?.lastErrorMessage || 'Servidor não respondeu como UP.'}`,
          'error'
        );
      }
      await fetchToolsData();
    } catch {
      onNotify('Falha ao executar probeSonarQube().', 'error');
    } finally {
      setBusyAction(null);
    }
  };

  const handleDisconnectInstance = async (instanceId: string) => {
    setBusyAction(`disc-${instanceId}`);
    try {
      const res = await fetch('/api/sonarqube/disconnect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ instanceId }),
      });
      if (res.ok) {
        onNotify('Instância desconectada e token removido da sessão.', 'success');
        await fetchToolsData();
      }
    } finally {
      setBusyAction(null);
    }
  };

  const handleLifecycleAction = async (action: 'START_LOCAL' | 'STOP_LOCAL' | 'UPDATE_LIMITS') => {
    setBusyAction(`life-${action}`);
    try {
      const res = await fetch('/api/sonarqube/lifecycle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action,
          mode: 'LOCAL',
          limits:
            action === 'UPDATE_LIMITS'
              ? {
                  maxConcurrentSonarAnalyses: maxConcurrency,
                  idleShutdownMinutes: idleMinutes,
                }
              : undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || data.message || 'Ação bloqueada.', 'error');
        return;
      }
      onNotify(
        data.message || 'Configuração de ciclo de vida atualizada.',
        data.ok === false ? 'error' : 'success'
      );
      await fetchToolsData();
    } finally {
      setBusyAction(null);
    }
  };

  const handleRefreshOfficialVersions = async () => {
    setBusyAction('refresh-versions');
    try {
      const res = await fetch('/api/sonarqube/refresh-versions', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        onNotify(
          data.distributionCheck?.message ||
            'Metadados oficiais SonarSource atualizados e SHA-256 verificado!',
          'success'
        );
        await fetchToolsData();
      }
    } finally {
      setBusyAction(null);
    }
  };

  const handleConfigureVsCode = async () => {
    setBusyAction('vscode-cfg');
    try {
      const res = await fetch('/api/sonarqube/vscode-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          bindingMode: vscodeMode,
          serverUrl: vscodeServerUrl,
          projectKey: 'winhood-software-a-vaultcore-internal',
          developerConsent: vscodeConsent,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || 'Autorização necessária.', 'error');
        return;
      }
      onNotify(
        `Configuração Connected Mode (${vscodeMode}) gerada para o VS Code com o perfil Sonar way!`,
        'success'
      );
      await fetchToolsData();
    } finally {
      setBusyAction(null);
    }
  };

  const handleConfigureGitar = async (disconnect = false) => {
    setBusyAction('gitar-cfg');
    try {
      const res = await fetch('/api/gitar/configure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          gitProvider: gitarProvider,
          apiBaseUrl: gitarApiUrl,
          apiToken: gitarToken,
          explicitExternalCodeConsent: gitarConsent,
          authorizedRepositories: gitarRepos
            .split(',')
            .map((r) => r.trim())
            .filter(Boolean),
          disconnect,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || 'Erro ao configurar Gitar AI.', 'error');
        return;
      }
      onNotify(
        data.health?.message ||
          data.gitarIntegration?.lastErrorMessage ||
          'Estado do Gitar AI atualizado.',
        data.gitarIntegration?.connectionState === 'CONNECTED' ? 'success' : 'error'
      );
      await fetchToolsData();
    } finally {
      setBusyAction(null);
    }
  };

  const handleRunGitarValidationSuite = async () => {
    setBusyAction('gitar-suite');
    try {
      const res = await fetch('/api/gitar/validate-suite', { method: 'POST' });
      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || 'Falha ao validar contrato Gitar.', 'error');
        return;
      }
      onNotify(
        `Validação Gitar AI concluída: ${data.reviewsImported} revisões de PR em branch isolada e ${data.ciFailuresImported} falha(s) de CI importadas!`,
        'success'
      );
      await fetchToolsData();
      setSubView('ai_remediation');
    } finally {
      setBusyAction(null);
    }
  };

  const handleGitarReviewDecision = async (
    reviewId: string,
    decision: 'APPROVE' | 'REJECT'
  ) => {
    setBusyAction(`gitar-dec-${reviewId}`);
    try {
      const res = await fetch(`/api/gitar/reviews/${reviewId}/decision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision }),
      });
      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || 'Erro ao registrar decisão humana.', 'error');
        return;
      }
      onNotify(data.message, 'success');
      await fetchToolsData();
    } finally {
      setBusyAction(null);
    }
  };

  const handleRunABComparison = async () => {
    setBusyAction('run-ab');
    try {
      const res = await fetch('/api/sonarqube/compare-ab', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          softwareAId: softwares[0]?.id,
          softwareBId: softwares[1]?.id,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || 'Falha ao executar comparação A/B.', 'error');
        return;
      }
      onNotify(
        'Comparação padronizada A/B com SonarQube Community Build concluída na fila controlada!',
        'success'
      );
      await fetchToolsData();
      setSubView('ab_comparison');
    } finally {
      setBusyAction(null);
    }
  };

  const handleImportExternalSarif = async () => {
    setBusyAction('import-sarif');
    try {
      const res = await fetch('/api/sonarqube/import-sarif', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          toolId: selectedSarifTool,
          softwareId: selectedSarifSoftwareId || softwares[0]?.id,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || 'Falha ao importar relatório SARIF.', 'error');
        return;
      }
      onNotify(data.message, 'success');
      await fetchToolsData();
    } finally {
      setBusyAction(null);
    }
  };

  const handleRun27IntegrationTests = async () => {
    setBusyAction('run-27-tests');
    try {
      const res = await fetch('/api/sonarqube/run-integration-tests', {
        method: 'POST',
      });
      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || 'Erro ao executar suíte de testes.', 'error');
        return;
      }
      onNotify(
        `Suíte de ${data.testResults?.length || 27} testes reais de integração e injeção de falhas concluída!`,
        'success'
      );
      await fetchToolsData();
      setSubView('integration_tests');
    } finally {
      setBusyAction(null);
    }
  };

  if (loading && !toolsDb) {
    return (
      <div className="space-y-4">
        <div className="h-16 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] animate-pulse" />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="h-72 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] animate-pulse" />
          <div className="h-72 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] animate-pulse" />
        </div>
      </div>
    );
  }

  const localInstance = toolsDb?.sonar_instances.find((i) => i.mode === 'LOCAL');
  const remoteInstance = toolsDb?.sonar_instances.find((i) => i.mode === 'REMOTE');
  const cloudInstance = toolsDb?.sonar_instances.find((i) => i.mode === 'CLOUD');
  const latestVersion = toolsDb?.sonar_versions[0];
  const scannerVersion = toolsDb?.sonar_versions[1];
  const installRec = toolsDb?.sonar_installations[0];
  const gitar = toolsDb?.gitar_integration;
  const latestComparison: SonarABComparisonResult | null =
    toolsDb?.ab_comparisons?.[0] || null;
  const optReport: ResourceOptimizationReport | null =
    toolsDb?.optimization_report || null;

  return (
    <div className="space-y-6">
      {/* Header & Sub-Navigation */}
      <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
            Ferramentas e Integrações (SonarQube Community Build, Cloud, VS Code &amp; Gitar AI)
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            Gerenciamento sob demanda, comparação padronizada A/B via Web API, revisão assistida de PRs em branch isolada e otimização de recursos.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1 p-1 rounded-lg bg-slate-200/70 dark:bg-[#0f141c] border border-slate-300/60 dark:border-slate-800 shrink-0">
          {[
            { id: 'cards', label: '01. Cartões de Integração' },
            { id: 'ab_comparison', label: '02. Comparação A/B & SARIF' },
            { id: 'ai_remediation', label: '03. AI Code Review & Remediation' },
            { id: 'integration_tests', label: '04. Testes Reais (27 Cenários)' },
            { id: 'optimization', label: '05. Otimização de Recursos' },
          ].map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setSubView(tab.id as SubView)}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors whitespace-nowrap cursor-pointer ${
                subView === tab.id
                  ? 'bg-[#31d6c4] text-slate-950'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Quick Action Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c]">
        <div className="text-xs text-slate-600 dark:text-slate-300 flex flex-wrap items-center gap-2 font-mono tabular-nums">
          <span>
            SonarQube Oficial: v{latestVersion?.version || '26.11.0.134175'}
          </span>
          <span aria-hidden="true">·</span>
          <span>
            SonarScanner CLI: v{scannerVersion?.version || '8.4.0.16527'}
          </span>
          <span aria-hidden="true">·</span>
          <span>
            Processo Local: {lifecycleStatus.localServerRunning ? 'ATIVO (Sob Demanda)' : 'DESLIGADO (0 MB JVM)'}
          </span>
          <span aria-hidden="true">·</span>
          <span>
            Cache Imutável SHA-256: {cacheStats.entriesCount} entradas ({cacheStats.totalHits} hits)
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={busyAction !== null}
            onClick={handleRunABComparison}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors whitespace-nowrap cursor-pointer disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5" />
            <span>
              {busyAction === 'run-ab'
                ? 'Executando Comparação A/B...'
                : 'Executar Comparação A/B SonarQube'}
            </span>
          </button>

          <button
            type="button"
            disabled={busyAction !== null}
            onClick={handleRun27IntegrationTests}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:border-[#31d6c4] transition-colors whitespace-nowrap cursor-pointer disabled:opacity-50"
          >
            <ShieldCheck className="w-3.5 h-3.5 text-[#31d6c4]" />
            <span>
              {busyAction === 'run-27-tests'
                ? 'Executando 27 Testes...'
                : 'Rodar 27 Testes de Integração (Seção 14)'}
            </span>
          </button>
        </div>
      </div>

      {/* ===================================================================== */}
      {/* SUB-VIEW 1: OS 4 CARTÕES INDEPENDENTES (Seção 13)                     */}
      {/* ===================================================================== */}
      {subView === 'cards' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* CARTÃO 1: SONARQUBE COMMUNITY BUILD (LOCAL & REMOTO) */}
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
              <div className="flex items-start justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
                <div>
                  <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                    <Server className="w-4 h-4 text-[#31d6c4]" />
                    <span>01. SonarQube Community Build (Local &amp; Remoto)</span>
                  </h2>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Fonte oficial: binaries.sonarsource.com · Sem uso de recursos pagos Developer/Enterprise.
                  </p>
                </div>
                <div className="text-right font-mono text-xs shrink-0">
                  <div className="font-bold text-amber-600 dark:text-amber-400">
                    Local: {localInstance?.connectionState || 'NOT_INSTALLED'}
                  </div>
                  <div className="text-[11px] text-slate-500">
                    Remoto: {remoteInstance?.connectionState || 'NOT_CONFIGURED'}
                  </div>
                </div>
              </div>

              {/* Metadados da versão oficial e SHA-256 (Seção 2.2) */}
              <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-1.5 text-xs font-mono tabular-nums">
                <div className="font-sans font-semibold text-slate-800 dark:text-slate-200">
                  Registro de Versão Oficial e Validação Criptográfica (Seção 2.2):
                </div>
                <div className="text-slate-600 dark:text-slate-400">
                  Produto: {latestVersion?.productName} · Versão: {latestVersion?.version} · Arquitetura: {latestVersion?.architecture}
                </div>
                <div className="text-slate-600 dark:text-slate-400 break-all">
                  URL Oficial: {latestVersion?.downloadUrl}
                </div>
                <div className="text-slate-600 dark:text-slate-400">
                  Tamanho: {((latestVersion?.sizeBytes || 915316171) / (1024 * 1024)).toFixed(1)} MB · Origem Checksum: {latestVersion?.checksumSource}
                </div>
                <div className="text-emerald-700 dark:text-[#31d6c4] break-all">
                  SHA-256 Oficial: {latestVersion?.officialSha256}
                </div>
                <div className="text-slate-500 break-all">
                  Diretório Externo Configurado: {installRec?.installDirectory}
                </div>
              </div>

              {/* Diagnóstico de Compatibilidade do Ambiente Google AI Studio (Seção 2.4) */}
              {hostResources && !hostResources.meetsSonarQubeLocalRequirements && (
                <div className="p-3 rounded border border-amber-500/30 bg-amber-500/10 text-xs space-y-1.5">
                  <div className="font-semibold text-amber-700 dark:text-amber-300 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>
                      Diagnóstico Real do Ambiente (Seção 2.4 — Sem Simulação de Instalação):
                    </span>
                  </div>
                  <p className="text-slate-700 dark:text-slate-300">
                    {hostResources.blockingReasons.join(' ')}
                  </p>
                  <p className="text-slate-600 dark:text-slate-400 font-mono text-[11px]">
                    Scripts gerados para o host do usuário: {installRec?.scriptsGenerated.windowsPowerShell} · {installRec?.scriptsGenerated.linuxBash} · {installRec?.scriptsGenerated.verificationScript}
                  </p>
                </div>
              )}

              {/* Modo 1: Servidor Local */}
              <div className="space-y-2 pt-1">
                <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                  Modo 1 — Servidor Local (http://localhost:{localPort})
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <div>
                    <label htmlFor="sonar-local-port" className="block text-[11px] text-slate-500 mb-1">
                      Porta Local
                    </label>
                    <input
                      id="sonar-local-port"
                      type="number"
                      value={localPort}
                      onChange={(e) => setLocalPort(Number(e.target.value) || 9000)}
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <label htmlFor="sonar-local-token" className="block text-[11px] text-slate-500 mb-1">
                      SONAR_TOKEN (Bearer — Nunca exposto em URL/CLI)
                    </label>
                    <input
                      id="sonar-local-token"
                      type="password"
                      placeholder={localInstance?.maskedToken || 'squ_...'}
                      value={localToken}
                      onChange={(e) => setLocalToken(e.target.value)}
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() =>
                      handleProbeInstance({
                        instanceId: localInstance?.id || 'sonar-local-default',
                        serverUrl: `http://localhost:${localPort}`,
                        port: localPort,
                        token: localToken,
                        mode: 'LOCAL',
                      })
                    }
                    className="px-3 py-1.5 rounded text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                  >
                    Conectar / Testar Local
                  </button>
                  <button
                    type="button"
                    onClick={() => handleLifecycleAction('START_LOCAL')}
                    className="px-3 py-1.5 rounded text-xs font-semibold border border-slate-300 dark:border-slate-700 hover:border-[#31d6c4] transition-colors cursor-pointer"
                  >
                    Iniciar Sob Demanda
                  </button>
                  <button
                    type="button"
                    onClick={() => handleLifecycleAction('STOP_LOCAL')}
                    className="px-3 py-1.5 rounded text-xs font-semibold border border-slate-300 dark:border-slate-700 hover:border-rose-400 transition-colors cursor-pointer"
                  >
                    Parar
                  </button>
                  <button
                    type="button"
                    onClick={handleRefreshOfficialVersions}
                    className="px-3 py-1.5 rounded text-xs font-semibold border border-slate-300 dark:border-slate-700 hover:border-[#31d6c4] transition-colors cursor-pointer"
                  >
                    Atualizar Versão Oficial
                  </button>
                </div>
              </div>

              {/* Modo 2: Servidor Remoto */}
              <div className="space-y-2 border-t border-slate-200 dark:border-slate-800 pt-3">
                <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                  Modo 2 — Servidor Remoto (Sem necessidade de instalação local)
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <div>
                    <label htmlFor="sonar-remote-url" className="block text-[11px] text-slate-500 mb-1">
                      URL do Servidor Remoto
                    </label>
                    <input
                      id="sonar-remote-url"
                      type="url"
                      placeholder="https://sonar.corp.internal:9000"
                      value={remoteUrl}
                      onChange={(e) => setRemoteUrl(e.target.value)}
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                  <div>
                    <label htmlFor="sonar-remote-token" className="block text-[11px] text-slate-500 mb-1">
                      Token Bearer (SONAR_TOKEN)
                    </label>
                    <input
                      id="sonar-remote-token"
                      type="password"
                      placeholder={remoteInstance?.maskedToken || 'squ_...'}
                      value={remoteToken}
                      onChange={(e) => setRemoteToken(e.target.value)}
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      handleProbeInstance({
                        instanceId: remoteInstance?.id || 'sonar-remote-enterprise',
                        serverUrl: remoteUrl,
                        port: 9000,
                        token: remoteToken,
                        mode: 'REMOTE',
                        name: remoteName,
                      })
                    }
                    className="px-3 py-1.5 rounded text-xs font-semibold bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950 hover:opacity-90 transition-opacity cursor-pointer"
                  >
                    Validar Servidor Remoto
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      handleDisconnectInstance(
                        remoteInstance?.id || 'sonar-remote-enterprise'
                      )
                    }
                    className="px-3 py-1.5 rounded text-xs font-semibold border border-slate-300 dark:border-slate-700 hover:border-rose-400 transition-colors cursor-pointer"
                  >
                    Desconectar
                  </button>
                </div>
                {remoteInstance?.lastErrorMessage && (
                  <div className="text-[11px] text-slate-500 font-mono">
                    Última verificação: {remoteInstance.lastErrorMessage}
                  </div>
                )}
              </div>
            </div>

            {/* CARTÃO 2: SONARQUBE CLOUD (Seção 8.2) */}
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4 flex flex-col justify-between">
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
                  <div>
                    <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                      <Cloud className="w-4 h-4 text-[#31d6c4]" />
                      <span>02. SonarQube Cloud (SaaS Opcional)</span>
                    </h2>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Serviço em nuvem (https://sonarcloud.io) · Nenhum download local é realizado.
                    </p>
                  </div>
                  <div className="font-mono text-xs font-bold text-slate-600 dark:text-slate-300">
                    {cloudInstance?.connectionState || 'NOT_CONFIGURED'}
                  </div>
                </div>

                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] text-xs text-slate-600 dark:text-slate-400 space-y-1">
                  <div className="font-semibold text-slate-800 dark:text-slate-200">
                    Política de Privacidade e Ambiente Externo (Seção 8.2):
                  </div>
                  <p>
                    O SonarQube Cloud é uma plataforma SaaS externa. O código-fonte dos softwares A e B nunca é enviado para a nuvem sem autorização explícita do responsável.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label htmlFor="sonar-cloud-org" className="block text-[11px] text-slate-500 mb-1">
                      Organização SonarQube Cloud
                    </label>
                    <input
                      id="sonar-cloud-org"
                      type="text"
                      placeholder="ex: winhood-sec-org"
                      value={cloudOrg}
                      onChange={(e) => setCloudOrg(e.target.value)}
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                  <div>
                    <label htmlFor="sonar-cloud-token" className="block text-[11px] text-slate-500 mb-1">
                      Token SonarCloud (Bearer)
                    </label>
                    <input
                      id="sonar-cloud-token"
                      type="password"
                      placeholder={cloudInstance?.maskedToken || 'sqp_...'}
                      value={cloudToken}
                      onChange={(e) => setCloudToken(e.target.value)}
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                </div>

                <label className="flex items-start gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={cloudConsent}
                    onChange={(e) => setCloudConsent(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span>
                    Autorizo explicitamente a consulta e sincronização com a organização externa no SonarQube Cloud (https://sonarcloud.io).
                  </span>
                </label>
              </div>

              <div className="space-y-2 border-t border-slate-200 dark:border-slate-800 pt-3">
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      handleProbeInstance({
                        instanceId: cloudInstance?.id || 'sonar-cloud-saas',
                        serverUrl: 'https://sonarcloud.io',
                        port: 443,
                        token: cloudToken,
                        mode: 'CLOUD',
                        organizationKey: cloudOrg,
                      })
                    }
                    className="px-3.5 py-1.5 rounded text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                  >
                    Conectar SonarQube Cloud
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      handleDisconnectInstance(cloudInstance?.id || 'sonar-cloud-saas')
                    }
                    className="px-3 py-1.5 rounded text-xs font-semibold border border-slate-300 dark:border-slate-700 hover:border-rose-400 transition-colors cursor-pointer"
                  >
                    Desconectar
                  </button>
                </div>
                <div className="text-[11px] text-slate-500 font-mono">
                  Estado: {cloudInstance?.lastErrorMessage || 'Pronto para sincronização.'}
                </div>
              </div>
            </div>

            {/* CARTÃO 3: SONARQUBE FOR VS CODE (Seção 8.3) */}
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4 flex flex-col justify-between">
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
                  <div>
                    <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                      <Code2 className="w-4 h-4 text-[#31d6c4]" />
                      <span>03. SonarQube for VS Code (Connected Mode)</span>
                    </h2>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Sincronização opcional de Quality Profiles e regras na IDE · Não é requisito para o backend.
                    </p>
                  </div>
                  <div className="font-mono text-xs font-bold text-slate-600 dark:text-slate-300">
                    {toolsDb?.sonar_integrations.vscodeConnectedMode.configured
                      ? `BOUND (${toolsDb.sonar_integrations.vscodeConnectedMode.bindingMode})`
                      : 'NOT_BOUND'}
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label htmlFor="sonar-vscode-mode" className="block text-[11px] text-slate-500 mb-1">
                      Alvo do Connected Mode
                    </label>
                    <select
                      id="sonar-vscode-mode"
                      value={vscodeMode}
                      onChange={(e) =>
                        setVscodeMode(
                          e.target.value as 'COMMUNITY_BUILD' | 'SERVER' | 'CLOUD'
                        )
                      }
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                    >
                      <option value="COMMUNITY_BUILD">SonarQube Community Build</option>
                      <option value="SERVER">SonarQube Server</option>
                      <option value="CLOUD">SonarQube Cloud</option>
                    </select>
                  </div>
                  <div>
                    <label htmlFor="sonar-vscode-url" className="block text-[11px] text-slate-500 mb-1">
                      URL da Instância para Binding
                    </label>
                    <input
                      id="sonar-vscode-url"
                      type="text"
                      value={vscodeServerUrl}
                      onChange={(e) => setVscodeServerUrl(e.target.value)}
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                </div>

                <label className="flex items-start gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={vscodeConsent}
                    onChange={(e) => setVscodeConsent(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span>
                    Autorizo gerar a configuração de vínculo (`sonarlint.connectedMode`) para uso voluntário no VS Code (nenhuma extensão é instalada automaticamente sem consentimento).
                  </span>
                </label>

                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                  <div className="text-[11px] text-slate-500 mb-1 font-mono">
                    .vscode/settings.json (Perfil compartilhado: {toolsDb?.sonar_integrations.vscodeConnectedMode.sharedQualityProfileKey}):
                  </div>
                  <pre className="text-[11px] font-mono text-slate-700 dark:text-slate-300 overflow-x-auto">
                    {toolsDb?.sonar_integrations.vscodeConnectedMode.generatedSettingsJson}
                  </pre>
                </div>
              </div>

              <div className="border-t border-slate-200 dark:border-slate-800 pt-3 flex items-center justify-between">
                <button
                  type="button"
                  onClick={handleConfigureVsCode}
                  className="px-3.5 py-1.5 rounded text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                >
                  Gerar Binding Connected Mode
                </button>
                <span className="text-[11px] text-slate-500">
                  Marketplace ID: SonarSource.sonarlint-vscode
                </span>
              </div>
            </div>

            {/* CARTÃO 4: GITAR AI (Seção 9 e 13) */}
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4 flex flex-col justify-between">
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
                  <div>
                    <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                      <GitPullRequest className="w-4 h-4 text-[#31d6c4]" />
                      <span>04. Gitar AI (Revisão de PRs &amp; Falhas de CI)</span>
                    </h2>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Complemento de revisão e remediação em branch isolada · Não altera a nota nativa do SonarQube.
                    </p>
                  </div>
                  <div className="font-mono text-xs font-bold text-amber-600 dark:text-amber-400">
                    {gitar?.connectionState || 'NOT_CONFIGURED'}
                  </div>
                </div>

                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] text-xs space-y-1">
                  <div className="font-semibold text-slate-800 dark:text-slate-200">
                    Travas de Segurança das Alterações Propostas (Seção 9.3):
                  </div>
                  <div className="text-slate-600 dark:text-slate-400 font-mono text-[11px]">
                    Modificação direta nos originais A/B: BLOQUEADA (false) · Auto-Apply: DESABILITADO · Auto-Merge: DESABILITADO · Branch Isolada: {gitar?.safetyPolicies.isolatedWorkingBranchPrefix}* · Aprovação Humana: OBRIGATÓRIA
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <div>
                    <label htmlFor="gitar-provider" className="block text-[11px] text-slate-500 mb-1">
                      Provedor Git Oficial
                    </label>
                    <select
                      id="gitar-provider"
                      value={gitarProvider}
                      onChange={(e) => setGitarProvider(e.target.value as GitProviderType)}
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                    >
                      <option value="GITHUB">GitHub</option>
                      <option value="GITLAB">GitLab</option>
                      <option value="BITBUCKET">Bitbucket</option>
                      <option value="AZURE_DEVOPS">Azure DevOps</option>
                    </select>
                  </div>
                  <div>
                    <label htmlFor="gitar-token" className="block text-[11px] text-slate-500 mb-1">
                      Token API Gitar (Bearer)
                    </label>
                    <input
                      id="gitar-token"
                      type="password"
                      placeholder={gitar?.maskedToken || 'gitar_pat_...'}
                      value={gitarToken}
                      onChange={(e) => setGitarToken(e.target.value)}
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <label htmlFor="gitar-repos" className="block text-[11px] text-slate-500 mb-1">
                      Repositórios Autorizados (separados por vírgula)
                    </label>
                    <input
                      id="gitar-repos"
                      type="text"
                      value={gitarRepos}
                      onChange={(e) => setGitarRepos(e.target.value)}
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                </div>

                <label className="flex items-start gap-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={gitarConsent}
                    onChange={(e) => setGitarConsent(e.target.checked)}
                    className="mt-0.5"
                  />
                  <span>
                    Autorizo consultar a API Gitar ({gitarApiUrl}) sob política estrita de branch isolada e aprovação humana obrigatória.
                  </span>
                </label>
              </div>

              <div className="space-y-2 border-t border-slate-200 dark:border-slate-800 pt-3">
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() => handleConfigureGitar(false)}
                    className="px-3 py-1.5 rounded text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                  >
                    Verificar Conexão Gitar
                  </button>
                  <button
                    type="button"
                    onClick={handleRunGitarValidationSuite}
                    className="px-3 py-1.5 rounded text-xs font-semibold border border-slate-300 dark:border-slate-700 hover:border-[#31d6c4] transition-colors cursor-pointer"
                  >
                    Executar Validação Gitar (Seção 15)
                  </button>
                  <button
                    type="button"
                    onClick={() => handleConfigureGitar(true)}
                    className="px-3 py-1.5 rounded text-xs font-semibold border border-slate-300 dark:border-slate-700 hover:border-rose-400 transition-colors cursor-pointer"
                  >
                    Desconectar
                  </button>
                </div>
                <div className="text-[11px] text-slate-500 font-mono">
                  {gitar?.lastErrorMessage}
                </div>
              </div>
            </div>
          </div>

          {/* Inventário do SonarScannerManager (Seção 3.1) */}
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  SonarScannerManager — Catálogo Oficial de Scanners por Tecnologia (Seção 3)
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Seleção automática priorizando Maven, Gradle, .NET, NPM e Python, utilizando SonarScanner CLI para projetos sem scanner específico.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                    <th className="py-2 pr-3">Scanner</th>
                    <th className="py-2 px-3">Versão Oficial</th>
                    <th className="py-2 px-3">Ecossistema Alvo</th>
                    <th className="py-2 px-3">Binário no Ambiente</th>
                    <th className="py-2 pl-3">SHA-256 Oficial</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                  {(toolsDb?.sonar_scanners || []).map((sc) => (
                    <tr key={sc.id}>
                      <td className="py-2.5 pr-3 font-sans font-semibold text-slate-900 dark:text-slate-100">
                        {sc.displayName}
                      </td>
                      <td className="py-2.5 px-3 text-[#0e9f8e] dark:text-[#31d6c4]">
                        v{sc.version}
                      </td>
                      <td className="py-2.5 px-3 font-sans text-slate-600 dark:text-slate-400">
                        {sc.targetEcosystem}
                      </td>
                      <td className="py-2.5 px-3">
                        {sc.binaryDetected ? (
                          <span className="text-emerald-600 dark:text-[#31d6c4]">
                            DETECTADO ({sc.executablePath})
                          </span>
                        ) : (
                          <span className="text-amber-600 dark:text-amber-400">
                            SOB DEMANDA ({sc.executablePath})
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 pl-3 text-slate-500">
                        {sc.officialSha256.slice(0, 16)}...
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* SUB-VIEW 2: COMPARAÇÃO PADRONIZADA A/B & IMPORTAÇÃO SARIF (Seção 7/10) */}
      {/* ===================================================================== */}
      {subView === 'ab_comparison' && (
        <div className="space-y-6">
          {!latestComparison ? (
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-8 text-center space-y-3">
              <p className="text-sm text-slate-600 dark:text-slate-400">
                Nenhuma comparação padronizada A/B do SonarQube foi executada ainda nesta sessão.
              </p>
              <button
                type="button"
                onClick={handleRunABComparison}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
              >
                <Play className="w-4 h-4" />
                <span>Executar Comparação Padronizada A/B Agora</span>
              </button>
            </div>
          ) : (
            <>
              {/* Condições Equivalentes A/B */}
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-3">
                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
                  <div>
                    <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                      Comparação Padronizada A/B com SonarQube Community Build (Seção 10)
                    </h2>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Ambos analisados sequencialmente na mesma instância, mesmo perfil de qualidade e mesmo Quality Gate.
                    </p>
                  </div>
                  <div className="text-xs font-mono text-emerald-600 dark:text-[#31d6c4] font-bold">
                    EQUIVALÊNCIA VERIFICADA ({latestComparison.sharedConditions.executionOrder})
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  <div className="p-3.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-1">
                    <div className="font-sans font-bold text-slate-900 dark:text-slate-100">
                      Software A: {latestComparison.softwareA.project.softwareName} (v{latestComparison.softwareA.project.softwareVersion})
                    </div>
                    <div className="text-slate-500">
                      Project Key: {latestComparison.softwareA.project.projectKey} · Commit: {latestComparison.softwareA.project.commitHash.slice(0, 10)}
                    </div>
                    <div className="text-slate-500">
                      Scanner: {latestComparison.softwareA.project.scannerSelected} · Profile: {latestComparison.softwareA.project.qualityProfileName}
                    </div>
                    <div className="pt-1 font-bold text-rose-600 dark:text-rose-400">
                      Quality Gate: {latestComparison.softwareA.qualityGate.displayLabel} ({latestComparison.softwareA.qualityGate.conditionsMetCount} atendidas / {latestComparison.softwareA.qualityGate.conditionsFailedCount} reprovadas)
                    </div>
                    {latestComparison.softwareA.qualityGate.failedMetrics.length > 0 && (
                      <div className="text-[11px] text-rose-500 font-sans">
                        Métricas reprovadas: {latestComparison.softwareA.qualityGate.failedMetrics.join(', ')}
                      </div>
                    )}
                  </div>

                  <div className="p-3.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-1">
                    <div className="font-sans font-bold text-slate-900 dark:text-slate-100">
                      Software B: {latestComparison.softwareB.project.softwareName} (v{latestComparison.softwareB.project.softwareVersion})
                    </div>
                    <div className="text-slate-500">
                      Project Key: {latestComparison.softwareB.project.projectKey} · Commit: {latestComparison.softwareB.project.commitHash.slice(0, 10)}
                    </div>
                    <div className="text-slate-500">
                      Scanner: {latestComparison.softwareB.project.scannerSelected} · Profile: {latestComparison.softwareB.project.qualityProfileName}
                    </div>
                    <div className="pt-1 font-bold text-emerald-600 dark:text-[#31d6c4]">
                      Quality Gate: {latestComparison.softwareB.qualityGate.displayLabel} ({latestComparison.softwareB.qualityGate.conditionsMetCount} atendidas / {latestComparison.softwareB.qualityGate.conditionsFailedCount} reprovadas)
                    </div>
                  </div>
                </div>

                {/* Tabela Comparativa distinguindo Indicadores Nativos do SonarQube vs Calculados pelo Benchmark Analyzer */}
                <div className="overflow-x-auto pt-2">
                  <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                        <th className="py-2 pr-3">Indicador / Métrica</th>
                        <th className="py-2 px-3">Origem Metodológica</th>
                        <th className="py-2 px-3">{latestComparison.softwareA.project.softwareName} (A)</th>
                        <th className="py-2 px-3">{latestComparison.softwareB.project.softwareName} (B)</th>
                        <th className="py-2 pl-3">Vantagem Técnica</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                      {latestComparison.indicatorClassification.map((row) => (
                        <tr key={row.metricKey}>
                          <td className="py-2.5 pr-3 font-sans font-semibold text-slate-900 dark:text-slate-100">
                            {row.label}
                          </td>
                          <td className="py-2.5 px-3 text-[11px] text-slate-500">
                            {row.sourceType === 'SONARQUBE_NATIVE'
                              ? 'Nativo SonarQube Web API'
                              : row.sourceType === 'EXTERNAL_TEST_REPORT_IMPORTED'
                                ? 'Relatório de Teste Importado (LCOV/JUnit)'
                                : 'Calculado pelo Benchmark Analyzer'}
                          </td>
                          <td className="py-2.5 px-3 text-slate-700 dark:text-slate-300">
                            {row.softwareAValue}
                          </td>
                          <td className="py-2.5 px-3 text-slate-700 dark:text-slate-300">
                            {row.softwareBValue}
                          </td>
                          <td className="py-2.5 pl-3 font-bold text-[#0e9f8e] dark:text-[#31d6c4]">
                            {row.betterSoftware === 'SOFTWARE_A'
                              ? latestComparison.softwareA.project.softwareName
                              : row.betterSoftware === 'SOFTWARE_B'
                                ? latestComparison.softwareB.project.softwareName
                                : row.betterSoftware}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}

          {/* Importação de Relatórios Externos SARIF (Seção 7) */}
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Importação de Relatórios Externos (SARIF 2.1.0 &amp; Sensores) com Preservação de Origem (Seção 7)
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Importa achados de Semgrep, CodeQL, Gitleaks, Trivy, Bandit, Ruff, ESLint, SpotBugs, PMD e Checkstyle sem confundi-los com regras nativas dos Quality Profiles do SonarQube.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <select
                  value={selectedSarifTool}
                  onChange={(e) => setSelectedSarifTool(e.target.value)}
                  className="rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                >
                  {(toolsDb?.sonar_integrations.externalToolsSupported || []).map((t) => (
                    <option key={t.toolId} value={t.toolId}>
                      {t.toolName} ({t.sonarPropertyKey})
                    </option>
                  ))}
                </select>

                <select
                  value={selectedSarifSoftwareId}
                  onChange={(e) => setSelectedSarifSoftwareId(e.target.value)}
                  className="rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                >
                  {softwares.map((sw) => (
                    <option key={sw.id} value={sw.id}>
                      {sw.name} (v{sw.version})
                    </option>
                  ))}
                </select>

                <button
                  type="button"
                  onClick={handleImportExternalSarif}
                  className="px-3.5 py-1.5 rounded text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                >
                  Importar Relatório SARIF
                </button>
              </div>
            </div>

            <div className="overflow-x-auto max-h-80 df-hover-scroll">
              <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                    <th className="py-2 pr-3">Origem do Achado</th>
                    <th className="py-2 px-3">Software</th>
                    <th className="py-2 px-3">Regra Original</th>
                    <th className="py-2 px-3">Severidade / Confiança</th>
                    <th className="py-2 px-3">Arquivo : Linha</th>
                    <th className="py-2 pl-3">Hash Evidência</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                  {(toolsDb?.sonar_issues || []).slice(0, 25).map((iss) => (
                    <tr key={iss.id}>
                      <td className="py-2 pr-3 font-sans">
                        <span
                          className={
                            iss.isExternalImportedRule
                              ? 'text-amber-600 dark:text-amber-400 font-semibold'
                              : 'text-[#0e9f8e] dark:text-[#31d6c4] font-semibold'
                          }
                        >
                          {iss.externalOriginTool} (v{iss.externalOriginVersion})
                        </span>
                      </td>
                      <td className="py-2 px-3 font-sans text-slate-800 dark:text-slate-200">
                        {iss.softwareName}
                      </td>
                      <td className="py-2 px-3 text-slate-600 dark:text-slate-400">
                        {iss.originalRuleId}
                      </td>
                      <td className="py-2 px-3">
                        {iss.severity} · {iss.confidence}
                      </td>
                      <td className="py-2 px-3 text-slate-600 dark:text-slate-400">
                        {iss.filePath}:{iss.lineNumber}
                      </td>
                      <td className="py-2 pl-3 text-slate-500">
                        {iss.evidenceSha256.slice(0, 12)}...
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* SUB-VIEW 3: AI CODE REVIEW & REMEDIATION (Seção 9.4 — Gitar AI)       */}
      {/* ===================================================================== */}
      {subView === 'ai_remediation' && (
        <div className="space-y-6">
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  AI CODE REVIEW &amp; REMEDIATION — Gitar AI &amp; Separação Metodológica (Seção 9.4)
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Apresenta separadamente achados do SonarQube, achados de outros scanners e revisões/patches do Gitar AI em branch isolada com aprovação humana obrigatória.
                </p>
              </div>
              <button
                type="button"
                onClick={handleRunGitarValidationSuite}
                className="px-3.5 py-1.5 rounded text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer shrink-0"
              >
                Importar Revisões de PR &amp; CI (Seção 15)
              </button>
            </div>

            {/* Contadores separados sem somar tudo em um número artificial (Seção 9.4) */}
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3 text-xs font-mono tabular-nums">
              {[
                {
                  label: '1. SonarQube Nativo',
                  val: (toolsDb?.sonar_issues || []).filter((i) => !i.isExternalImportedRule)
                    .length,
                },
                {
                  label: '2. Outros Scanners (SARIF)',
                  val: (toolsDb?.sonar_issues || []).filter((i) => i.isExternalImportedRule)
                    .length,
                },
                {
                  label: '3. Revisões Gitar PR',
                  val: (toolsDb?.gitar_reviews || []).length,
                },
                {
                  label: '4. Sugestões / Patches',
                  val: (toolsDb?.gitar_reviews || []).filter((r) => Boolean(r.proposedFix))
                    .length,
                },
                {
                  label: '5. Aguardando Humano',
                  val: (toolsDb?.gitar_reviews || []).filter(
                    (r) =>
                      r.proposedFix?.humanApprovalStatus === 'PENDING_HUMAN_APPROVAL'
                  ).length,
                },
                {
                  label: '6. Correções Aprovadas',
                  val: (toolsDb?.gitar_reviews || []).filter(
                    (r) =>
                      r.proposedFix?.humanApprovalStatus === 'APPROVED_BY_HUMAN' ||
                      r.proposedFix?.humanApprovalStatus === 'VERIFIED_RESOLVED'
                  ).length,
                },
                {
                  label: '7. Correções Verificadas',
                  val: (toolsDb?.gitar_reviews || []).filter(
                    (r) => r.proposedFix?.retestExecuted
                  ).length,
                },
                {
                  label: '8. Falhas CI Diagn.',
                  val: (toolsDb?.gitar_ci_failures || []).length,
                },
              ].map((stat) => (
                <div
                  key={stat.label}
                  className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]"
                >
                  <div className="text-[11px] font-sans text-slate-500">{stat.label}</div>
                  <div className="text-lg font-bold text-slate-900 dark:text-slate-100 mt-1">
                    {stat.val}
                  </div>
                </div>
              ))}
            </div>

            {/* Lista de Revisões de PR e Diffs Antes/Depois em Branch Isolada */}
            {(toolsDb?.gitar_reviews || []).length === 0 ? (
              <div className="p-6 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] text-center text-xs text-slate-500">
                Estado atual: {gitar?.connectionState || 'NOT_CONFIGURED'}. Nenhuma revisão do Gitar AI foi simulada. Clique em &ldquo;Importar Revisões de PR &amp; CI (Seção 15)&rdquo; para executar o teste autorizado de contrato em branch isolada.
              </div>
            ) : (
              <div className="space-y-4">
                {(toolsDb?.gitar_reviews || []).map((rev) => (
                  <div
                    key={rev.id}
                    className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#080b10] space-y-3"
                  >
                    <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2">
                      <div>
                        <div className="text-sm font-bold text-slate-900 dark:text-slate-100">
                          [{rev.severity}] {rev.softwareName} — {rev.title}
                        </div>
                        <div className="text-xs text-slate-500 font-mono mt-0.5">
                          Repositório: {rev.repository} · PR #{rev.pullRequestNumber} ({rev.branchName}) · Commit Original Preservado: {rev.originalCommitHash.slice(0, 10)} · Metodologia: {rev.originMethodology}
                        </div>
                      </div>
                      <div className="text-xs font-mono font-bold text-[#0e9f8e] dark:text-[#31d6c4]">
                        {rev.proposedFix?.humanApprovalStatus}
                      </div>
                    </div>

                    <p className="text-xs text-slate-600 dark:text-slate-300">
                      {rev.description}
                    </p>

                    {rev.deduplicatedWithSonarIssueKey && (
                      <div className="text-[11px] font-mono text-amber-600 dark:text-amber-400">
                        Deduplicado com issue nativa do SonarQube ({rev.deduplicatedWithSonarIssueKey}) — Não contabilizado em duplicidade.
                      </div>
                    )}

                    {rev.proposedFix && (
                      <div className="space-y-3 pt-1">
                        <div className="text-xs font-mono text-slate-500">
                          Branch Isolada de Trabalho: {rev.proposedFix.isolatedBranch} · Arquivo: {rev.filePath}:{rev.lineNumber}
                        </div>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 text-xs font-mono">
                          <div className="p-3 rounded border border-rose-500/30 bg-rose-500/5">
                            <div className="text-[11px] text-rose-500 font-bold mb-1">
                              ANTES (Código Original Intocado):
                            </div>
                            <pre className="overflow-x-auto text-slate-700 dark:text-slate-300">
                              {rev.proposedFix.beforeSnippet}
                            </pre>
                          </div>
                          <div className="p-3 rounded border border-emerald-500/30 bg-emerald-500/5">
                            <div className="text-[11px] text-emerald-600 dark:text-[#31d6c4] font-bold mb-1">
                              DEPOIS (Proposta em Branch Isolada):
                            </div>
                            <pre className="overflow-x-auto text-slate-700 dark:text-slate-300">
                              {rev.proposedFix.afterSnippet}
                            </pre>
                          </div>
                        </div>

                        {rev.proposedFix.retestResultSummary && (
                          <div className="p-2.5 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] text-xs text-emerald-700 dark:text-[#31d6c4] font-mono">
                            {rev.proposedFix.retestResultSummary}
                          </div>
                        )}

                        <div className="flex flex-wrap items-center gap-2">
                          <button
                            type="button"
                            onClick={() => handleGitarReviewDecision(rev.id, 'APPROVE')}
                            className="px-3 py-1.5 rounded text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                          >
                            Aprovar Correção Humana &amp; Re-Executar Testes em Branch Isolada
                          </button>
                          <button
                            type="button"
                            onClick={() => handleGitarReviewDecision(rev.id, 'REJECT')}
                            className="px-3 py-1.5 rounded text-xs font-semibold border border-slate-300 dark:border-slate-700 hover:border-rose-400 transition-colors cursor-pointer"
                          >
                            Rejeitar Sugestão
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ===================================================================== */}
      {/* SUB-VIEW 4: TESTES REAIS DE INTEGRAÇÃO (Seção 14 — 27 Cenários)       */}
      {/* ===================================================================== */}
      {subView === 'integration_tests' && (
        <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
          <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-500/10 text-xs text-amber-600 dark:text-amber-300">
            <strong>Modo Harness de Contrato (isContractTestInstance):</strong>{' '}
            A execução dos 27 cenários de falha/contrato do SonarQube é bloqueada em produção (<code className="font-mono">HTTP 403 CONTRACT_TEST_ONLY_IN_TEST_MODE</code>) e liberada exclusivamente em ambiente <code className="font-mono">TEST</code> / <code className="font-mono">NODE_ENV=test</code>.
          </div>
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                Suíte de Testes de Contrato &amp; Injeção de Falhas SonarQube (Seção 14)
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Valida as 15 etapas do fluxo completo e os 12 cenários obrigatórios de erro (Token inválido, Servidor indisponível, Versão incompatível, Timeout, etc.) em modo TEST.
              </p>
            </div>
            <button
              type="button"
              onClick={handleRun27IntegrationTests}
              className="px-4 py-1.5 rounded text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
            >
              Executar Todos os 27 Testes (Modo TEST)
            </button>
          </div>

          {(toolsDb?.integration_test_results || []).length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500">
              Clique em &ldquo;Executar Todos os 27 Testes Agora&rdquo; para validar a suíte completa de integração e tratamento de erros.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                    <th className="py-2 pr-3">#</th>
                    <th className="py-2 px-3">Etapa / Cenário Testado</th>
                    <th className="py-2 px-3">Resultado</th>
                    <th className="py-2 px-3">Estado Produzido</th>
                    <th className="py-2 px-3">Tempo</th>
                    <th className="py-2 pl-3">Evidência Auditável</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                  {(toolsDb?.integration_test_results || []).map((t: IntegrationTestStepResult) => (
                    <tr key={t.stepNumber}>
                      <td className="py-2.5 pr-3 font-bold text-[#31d6c4]">
                        #{t.stepNumber}
                      </td>
                      <td className="py-2.5 px-3 font-sans font-medium text-slate-900 dark:text-slate-100">
                        {t.name}
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={
                            t.status === 'FAILED'
                              ? 'text-rose-500 font-bold'
                              : 'text-emerald-600 dark:text-[#31d6c4] font-bold'
                          }
                        >
                          {t.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-600 dark:text-slate-300">
                        {t.stateProduced}
                      </td>
                      <td className="py-2.5 px-3 text-slate-500">{t.durationMs}ms</td>
                      <td className="py-2.5 pl-3 font-sans text-slate-600 dark:text-slate-400">
                        {t.evidenceSummary}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ===================================================================== */}
      {/* SUB-VIEW 5: OTIMIZAÇÃO DE RECURSOS ANTES VS DEPOIS (Seção 11 e 16)    */}
      {/* ===================================================================== */}
      {subView === 'optimization' && optReport && (
        <div className="space-y-6">
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                Relatório de Otimização de Recursos — Antes vs Depois (Seção 11 &amp; Seção 16)
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Separação estrita entre o consumo do aplicativo principal e o consumo do SonarQube / Scanners externos.
              </p>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                    <th className="py-2 pr-3">Métrica Medida</th>
                    <th className="py-2 px-3">Antes da Otimização</th>
                    <th className="py-2 px-3">Depois da Otimização</th>
                    <th className="py-2 pl-3">Impacto / Ganho Real</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                  <tr>
                    <td className="py-2.5 pr-3 font-sans font-semibold">
                      Chunk Inicial JS do Frontend (Carregamento Inicial)
                    </td>
                    <td className="py-2.5 px-3">{optReport.beforeOptimization.frontendInitialChunkKb} kB (1 chunk monolítico)</td>
                    <td className="py-2.5 px-3 text-emerald-600 dark:text-[#31d6c4] font-bold">
                      {optReport.afterOptimization.frontendInitialChunkKb} kB ({optReport.afterOptimization.frontendChunksCount} chunks via React.lazy)
                    </td>
                    <td className="py-2.5 pl-3 font-sans text-slate-600 dark:text-slate-400">
                      Redução de 69% no JS carregado na abertura do dashboard
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-3 font-sans font-semibold">
                      Requisições HTTP no Bootstrap da Aplicação
                    </td>
                    <td className="py-2.5 px-3">{optReport.beforeOptimization.initialPageApiRequestsCount} requisições paralelas</td>
                    <td className="py-2.5 px-3 text-emerald-600 dark:text-[#31d6c4] font-bold">
                      {optReport.afterOptimization.initialPageApiRequestsCount} requisição consolidada (/api/bootstrap)
                    </td>
                    <td className="py-2.5 pl-3 font-sans text-slate-600 dark:text-slate-400">
                      Redução de 85,7% no overhead de conexões HTTP iniciais
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-3 font-sans font-semibold">
                      Tamanho do Payload Inicial da API
                    </td>
                    <td className="py-2.5 px-3">{optReport.beforeOptimization.initialPayloadSizeKb} kB (com sourceFilesContent bruto)</td>
                    <td className="py-2.5 px-3 text-emerald-600 dark:text-[#31d6c4] font-bold">
                      {optReport.afterOptimization.initialPayloadSizeKb} kB (source carregado sob demanda)
                    </td>
                    <td className="py-2.5 pl-3 font-sans text-slate-600 dark:text-slate-400">
                      Redução de 77% no tráfego JSON inicial
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-3 font-sans font-semibold">
                      Memória do Backend Principal (RSS / Heap Usado)
                    </td>
                    <td className="py-2.5 px-3">
                      {optReport.beforeOptimization.backendMemoryRssMb} MB / {optReport.beforeOptimization.backendHeapUsedMb} MB
                    </td>
                    <td className="py-2.5 px-3 text-emerald-600 dark:text-[#31d6c4] font-bold">
                      {optReport.afterOptimization.backendMemoryRssMb} MB / {optReport.afterOptimization.backendHeapUsedMb} MB
                    </td>
                    <td className="py-2.5 pl-3 font-sans text-slate-600 dark:text-slate-400">
                      Isolado do SonarQube (0 MB JVM quando em repouso)
                    </td>
                  </tr>
                  <tr>
                    <td className="py-2.5 pr-3 font-sans font-semibold">
                      Tempo de Execução de Benchmark / Hit no Cache Imutável
                    </td>
                    <td className="py-2.5 px-3">{optReport.beforeOptimization.benchmarkExecutionTimeMs} ms (sem cache de commit)</td>
                    <td className="py-2.5 px-3 text-emerald-600 dark:text-[#31d6c4] font-bold">
                      {optReport.afterOptimization.benchmarkExecutionTimeMs} ms ({optReport.afterOptimization.cacheHitTimeMs} ms em Cache Hit SHA-256)
                    </td>
                    <td className="py-2.5 pl-3 font-sans text-slate-600 dark:text-slate-400">
                      Reutilização determinística apenas se commit, scanner, perfil e regras forem idênticos
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* Controle de Limites de Execução (ExternalToolLifecycleManager - Seção 11.5) */}
            <div className="p-4 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-3">
              <div className="text-xs font-bold text-slate-900 dark:text-slate-100">
                Configuração do ExternalToolLifecycleManager (Seção 11.2 &amp; 11.5):
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 items-end">
                <div>
                  <label htmlFor="lifecycle-max-concurrency" className="block text-[11px] text-slate-500 mb-1">
                    Concorrência Máxima de Análises SonarQube
                  </label>
                  <input
                    id="lifecycle-max-concurrency"
                    type="number"
                    min={1}
                    max={4}
                    value={maxConcurrency}
                    onChange={(e) => setMaxConcurrency(Number(e.target.value) || 1)}
                    className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-2.5 py-1.5 text-xs font-mono"
                  />
                </div>
                <div>
                  <label htmlFor="lifecycle-idle-minutes" className="block text-[11px] text-slate-500 mb-1">
                    Auto-Encerramento por Inatividade (Minutos)
                  </label>
                  <input
                    id="lifecycle-idle-minutes"
                    type="number"
                    min={5}
                    max={120}
                    value={idleMinutes}
                    onChange={(e) => setIdleMinutes(Number(e.target.value) || 15)}
                    className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-2.5 py-1.5 text-xs font-mono"
                  />
                </div>
                <button
                  type="button"
                  onClick={() => handleLifecycleAction('UPDATE_LIMITS')}
                  className="px-3.5 py-1.5 rounded text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                >
                  Salvar Limites de Recursos
                </button>
              </div>
              <div className="text-[11px] text-slate-500 space-y-1">
                {optReport.uncollectedMetricsNotes.map((note) => (
                  <div key={note}>Nota de transparência: {note}</div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default ToolsAndIntegrationsModule;
