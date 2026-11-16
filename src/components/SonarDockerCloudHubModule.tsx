import React, { useState, useEffect } from 'react';
import { csrfFetch as fetch } from '../utils/csrfFetch';
import {
  Server,
  Cloud,
  Terminal,
  Cpu,
  Copy,
  Check,
  RefreshCw,
  ExternalLink,
  ShieldCheck,
  Play,
  Layers,
  ArrowRight,
  Monitor,
  HardDrive,
  Zap,
  Download,
  KeyRound,
  Eye,
  EyeOff,
  Trash2,
  Clock,
  AlertTriangle,
  CheckCircle2,
  FileCode2,
  PlusCircle,
} from 'lucide-react';
import type { HardwareProfile } from '../engine/workerPool';
import type {
  SavedSonarProjectProfile,
  SonarHotspotsBreakdown,
  SonarMeasuresRecord,
  SonarPaginationSummary,
  SonarProfileVerificationState,
  SonarQualityGateRecord,
  SonarQualityModelMode,
  SonarTokenVerificationResult,
} from '../types/benchmark';
import { HairlineAnimatedFigure } from './HairlineAnimatedFigure';

interface SonarMethodologySummaryPayload {
  projectKey: string;
  organization: string;
  qualityModelMode: SonarQualityModelMode;
  qualityProfileVerification: {
    profileName: string;
    profileKey: string;
    language: string;
    isBuiltIn: boolean;
    isDefault: boolean;
    verificationState: SonarProfileVerificationState;
  };
  qualityGate: SonarQualityGateRecord;
  measures: SonarMeasuresRecord;
  hotspotsBreakdown: SonarHotspotsBreakdown;
  paginationSummary: {
    issuesPagination: SonarPaginationSummary;
    hotspotsPagination: SonarPaginationSummary;
  };
  scoreSeparation: {
    nativeSonarMetrics: {
      source: 'SONARCLOUD_OFFICIAL_API' | 'NOT_MEASURED';
      reliabilityRating: string;
      securityRating: string;
      maintainabilityRating: string;
      securityReviewRating: string;
      qualityGateStatus: string;
      nativeSonarCompositeReference: number | null;
    };
    winhoodCalculatedScore: {
      source: 'WINHOOD_CALCULATED';
      overallScore: number | null;
      securityScore: number | null;
      qualityScore: number | null;
      algorithmVersion: string;
      note: string;
    };
  };
}

interface SavedSonarProjectWithVerification
  extends Omit<SavedSonarProjectProfile, 'encryptedToken'> {
  tokenVerification?: SonarTokenVerificationResult;
}

interface SonarDockerStatus {
  dockerContainerSuggestedCommand: string;
  serverUrl: string;
  isReachable: boolean;
  connectionState: string;
  systemStatus: string | null;
  version: string | null;
  latencyMs: number;
  errorMessage: string | null;
}

interface Props {
  onNotify: (message: string, type?: 'success' | 'error') => void;
  onRefreshRun?: () => void;
}

export const SonarDockerCloudHubModule: React.FC<Props> = ({ onNotify, onRefreshRun }) => {
  const [activeTab, setActiveTab] = useState<'docker' | 'cloud' | 'scanner' | 'hardware'>('cloud');
  const [isHelpGuideOpen, setIsHelpGuideOpen] = useState(false);
  const [vaultStatus, setVaultStatus] = useState<{
    configured: boolean;
    organization: string;
    projectKey: string;
    hasToken: boolean;
    maskedToken: string | null;
  } | null>(null);

  // MqrBridge Docker state
  const [dockerStatus, setDockerStatus] = useState<SonarDockerStatus | null>(null);
  const [testingDocker, setTestingDocker] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // SonarScanner Generator state
  const [scannerEcosystem, setScannerEcosystem] = useState<'nodejs' | 'maven' | 'gradle' | 'dotnet' | 'cli'>('nodejs');
  const [projectKey, setProjectKey] = useState('');
  const [hostUrl, setHostUrl] = useState('');
  const [token, setToken] = useState('');

  // Nuvem MQR state
  const [cloudOrg, setCloudOrg] = useState('');
  const [cloudToken, setCloudToken] = useState('');
  const [testingCloud, setTestingCloud] = useState(false);
  const [cloudResult, setCloudResult] = useState<{ ok: boolean; message: string } | null>(null);

  // Hardware Acceleration state
  const [hardware, setHardware] = useState<HardwareProfile | null>(null);
  const [loadingHardware, setLoadingHardware] = useState(false);
  const [savingHardware, setSavingHardware] = useState(false);

  // Automatic Backend Docker & Quick Analysis state
  const [startingDocker, setStartingDocker] = useState(false);
  const [stoppingDocker, setStoppingDocker] = useState(false);
  const [runningQuickAnalysis, setRunningQuickAnalysis] = useState(false);

  // Saved Sonar Projects & 1-Click JSON Exporter state (Especificação 2)
  const [savedSonarProjects, setSavedSonarProjects] = useState<
    SavedSonarProjectWithVerification[]
  >([]);
  const [loadingSavedProjects, setLoadingSavedProjects] = useState(false);
  const [editingProfileId, setEditingProfileId] = useState<string | null>(null);
  const [profName, setProfName] = useState('');
  const [profPlatform, setProfPlatform] = useState<'SONARCLOUD' | 'MQR_BRIDGE_SERVER'>(
    'SONARCLOUD'
  );
  const [profServerUrl, setProfServerUrl] = useState('');
  const [profOrganization, setProfOrganization] = useState('');
  const [profProjectKey, setProfProjectKey] = useState('');
  const [profToken, setProfToken] = useState('');
  const [showProfToken, setShowProfToken] = useState(false);
  const [profValidityPolicy, setProfValidityPolicy] = useState<
    30 | 60 | 90 | 'NO_EXPIRATION' | 'CUSTOM'
  >(90);
  const [profCustomExpiresAt, setProfCustomExpiresAt] = useState('');
  const [savingProfile, setSavingProfile] = useState(false);
  const [verifyingProjectId, setVerifyingProjectId] = useState<string | null>(null);
  const [exportingJsonId, setExportingJsonId] = useState<string | null>(null);
  const [exportingPs1Id, setExportingPs1Id] = useState<string | null>(null);
  const [isExtractingDirect, setIsExtractingDirect] = useState(false);
  const [methodologySummary, setMethodologySummary] =
    useState<SonarMethodologySummaryPayload | null>(null);
  const [loadingMethodology, setLoadingMethodology] = useState(false);

  const loadMethodologySummary = async () => {
    setLoadingMethodology(true);
    try {
      const res = await fetch('/api/sonar/methodology-summary');
      if (res.ok) {
        const data = (await res.json()) as SonarMethodologySummaryPayload;
        setMethodologySummary(data);
      }
    } catch {
      // ignore
    } finally {
      setLoadingMethodology(false);
    }
  };

  const loadVaultStatus = async () => {
    try {
      const res = await fetch('/api/sonar/vault-status');
      if (res.ok) {
        const data = await res.json();
        setVaultStatus(data);
      }
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    void loadVaultStatus();
    void loadMethodologySummary();
  }, []);

  const loadSavedSonarProjects = async () => {
    setLoadingSavedProjects(true);
    try {
      const res = await fetch('/api/sonar/saved-projects');
      if (res.ok) {
        const data = (await res.json()) as {
          projects?: SavedSonarProjectWithVerification[];
        };
        if (Array.isArray(data.projects)) {
          setSavedSonarProjects(data.projects);
        }
      }
    } catch {
      // silent fallback
    } finally {
      setLoadingSavedProjects(false);
    }
  };

  const handleSelectProfileForEdit = (proj: SavedSonarProjectWithVerification) => {
    setEditingProfileId(proj.id);
    setProfName(proj.name);
    setProfPlatform(proj.platform);
    setProfServerUrl(proj.serverUrl);
    setProfOrganization(proj.organization);
    setProfProjectKey(proj.projectKey);
    setProfValidityPolicy(proj.tokenValidityDaysPolicy || 90);
    setProfCustomExpiresAt(
      proj.tokenExpiresAt ? proj.tokenExpiresAt.slice(0, 10) : ''
    );
    setProfToken('');
  };

  const handleSaveSonarProjectProfile = async () => {
    if (!profProjectKey.trim()) {
      onNotify('Informe o Project Key do projeto no Nuvem MQR / Servidor MQR.', 'error');
      return;
    }
    setSavingProfile(true);
    try {
      const res = await fetch('/api/sonar/saved-projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: editingProfileId || undefined,
          name: profName.trim() || profProjectKey.trim(),
          platform: profPlatform,
          serverUrl: profServerUrl.trim(),
          organization: profOrganization.trim(),
          projectKey: profProjectKey.trim(),
          token: profToken.trim() || undefined,
          tokenValidityDaysPolicy: profValidityPolicy,
          customTokenExpiresAt:
            profValidityPolicy === 'CUSTOM' && profCustomExpiresAt
              ? profCustomExpiresAt
              : null,
        }),
      });
      const data = (await res.json()) as {
        error?: string;
        projects?: SavedSonarProjectWithVerification[];
        project?: SavedSonarProjectWithVerification;
      };
      if (!res.ok) {
        onNotify(data.error || 'Falha ao salvar perfil do projeto Sonar.', 'error');
        return;
      }
      if (Array.isArray(data.projects)) {
        setSavedSonarProjects(data.projects);
      }
      if (data.project) {
        setEditingProfileId(data.project.id);
      }
      setProfToken('');
      onNotify(
        `Perfil "${profProjectKey.trim()}" salvo com sucesso (Token criptografado com AES-256-GCM).`,
        'success'
      );
    } catch {
      onNotify('Erro ao salvar perfil do projeto Sonar.', 'error');
    } finally {
      setSavingProfile(false);
    }
  };

  const handleVerifyProjectToken = async (projId: string) => {
    setVerifyingProjectId(projId);
    try {
      const res = await fetch(`/api/sonar/saved-projects/${projId}/verify-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token:
            editingProfileId === projId && profToken.trim()
              ? profToken.trim()
              : undefined,
        }),
      });
      const data = (await res.json()) as {
        error?: string;
        project?: SavedSonarProjectWithVerification;
        verification?: SonarTokenVerificationResult;
      };
      if (!res.ok) {
        onNotify(data.error || 'Erro ao verificar token.', 'error');
        return;
      }
      if (data.project) {
        setSavedSonarProjects((prev) =>
          prev.map((item) => (item.id === projId ? data.project! : item))
        );
      }
      onNotify(
        data.verification?.message || 'Status do token atualizado.',
        data.verification?.valid ? 'success' : 'error'
      );
    } catch {
      onNotify('Falha ao verificar validade do token.', 'error');
    } finally {
      setVerifyingProjectId(null);
    }
  };

  const handleDownloadSonarJsonReport = async (
    proj: SavedSonarProjectWithVerification
  ) => {
    if (!proj.hasToken && !(editingProfileId === proj.id && profToken.trim())) {
      handleSelectProfileForEdit(proj);
      onNotify(
        `Insira e salve seu Bearer Token do Nuvem MQR para o projeto "${proj.projectKey}" antes de baixar o relatório JSON.`,
        'error'
      );
      return;
    }

    setExportingJsonId(proj.id);
    try {
      // Se o usuário digitou o token no formulário mas ainda não clicou em Salvar, salva antes de exportar
      if (editingProfileId === proj.id && profToken.trim()) {
        await handleSaveSonarProjectProfile();
      }
      const res = await fetch(`/api/sonar/saved-projects/${proj.id}/export-json`);
      if (!res.ok) {
        const errJson = (await res.json().catch(() => ({}))) as { error?: string };
        onNotify(
          errJson.error ||
            `Falha HTTP ${res.status} ao exportar relatório JSON de "${proj.projectKey}".`,
          'error'
        );
        return;
      }
      const blob = await res.blob();
      const safeKey = proj.projectKey.replace(/[^a-zA-Z0-9._-]/g, '_');
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `winhood-mqr-report-${safeKey}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(downloadUrl);

      await loadSavedSonarProjects();
      if (onRefreshRun) {
        onRefreshRun();
      }
      onNotify(
        `Relatório winhood-mqr-report-${safeKey}.json baixado e achados sincronizados com o painel!`,
        'success'
      );
    } catch {
      onNotify('Erro de rede ao baixar relatório JSON do Nuvem MQR.', 'error');
    } finally {
      setExportingJsonId(null);
    }
  };

  const handleDirectOneClickExtract = async () => {
    const targetKey = profProjectKey.trim() || vaultStatus?.projectKey || 'LilNavaHoods_Winhood-Benchmarking';
    const targetOrg = profOrganization.trim() || vaultStatus?.organization || 'lilnavahoods';
    const targetToken = profToken.trim() || undefined;

    if (!targetToken && !vaultStatus?.hasToken) {
      onNotify('Informe o seu Bearer Token do Nuvem MQR para realizar a extração 1-Clique.', 'error');
      return;
    }

    setIsExtractingDirect(true);
    try {
      const res = await fetch('/api/sonar/export-full-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          organization: targetOrg,
          projectKey: targetKey,
          token: targetToken,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || 'Falha ao extrair dados do Nuvem MQR.', 'error');
        return;
      }

      // 1. Download do arquivo JSON no navegador
      const jsonStr = JSON.stringify(data.report, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const safeKey = targetKey.replace(/[^a-zA-Z0-9._-]/g, '_');
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `winhood-mqr-report-${safeKey}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(downloadUrl);

      // 2. Atualizar estado local e global
      await loadVaultStatus();
      await loadSavedSonarProjects();
      await loadMethodologySummary();
      if (onRefreshRun) {
        onRefreshRun();
      }

      setProfToken('');
      onNotify(
        data.message || `Relatório baixado e ${data.syncedFindingsCount || 0} achados sincronizados automaticamente!`,
        'success'
      );
    } catch {
      onNotify('Erro de conexão ao realizar a extração do Nuvem MQR.', 'error');
    } finally {
      setIsExtractingDirect(false);
    }
  };

  const handleDownloadSonarPs1Script = async (
    proj: SavedSonarProjectWithVerification
  ) => {
    setExportingPs1Id(proj.id);
    try {
      const res = await fetch(`/api/sonar/saved-projects/${proj.id}/export-ps1`);
      if (!res.ok) {
        onNotify('Falha ao gerar script PowerShell (.ps1).', 'error');
        return;
      }
      const blob = await res.blob();
      const safeKey = proj.projectKey.replace(/[^a-zA-Z0-9._-]/g, '_');
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `winhood-mqr-${safeKey}.ps1`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(downloadUrl);
      onNotify(
        `Script PowerShell completo winhood-mqr-${safeKey}.ps1 baixado (coleta Quality Gate, Métricas, Hotspots e Issues)!`,
        'success'
      );
    } catch {
      onNotify('Erro ao baixar script PowerShell (.ps1).', 'error');
    } finally {
      setExportingPs1Id(null);
    }
  };

  const handleDownloadFormPs1Script = async () => {
    setExportingPs1Id('form-direct');
    try {
      const res = await fetch('/api/sonar/export-ps1-direct', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          platform: profPlatform,
          serverUrl:
            profServerUrl.trim() ||
            (profPlatform === 'SONARCLOUD'
              ? 'https://sonarcloud.io'
              : 'http://localhost:9000'),
          projectKey: profProjectKey.trim(),
          organization: profOrganization.trim(),
          token: profToken.trim() || undefined,
        }),
      });
      if (!res.ok) {
        onNotify('Falha ao gerar script PowerShell (.ps1).', 'error');
        return;
      }
      const blob = await res.blob();
      const safeKey = (profProjectKey.trim() || 'sonar_project').replace(
        /[^a-zA-Z0-9._-]/g,
        '_'
      );
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = `winhood-mqr-${safeKey}.ps1`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(downloadUrl);
      onNotify(
        `Script PowerShell completo winhood-mqr-${safeKey}.ps1 baixado!`,
        'success'
      );
    } catch {
      onNotify('Erro ao baixar script PowerShell (.ps1).', 'error');
    } finally {
      setExportingPs1Id(null);
    }
  };

  const handleDeleteSavedProject = async (proj: SavedSonarProjectWithVerification) => {
    try {
      const res = await fetch(`/api/sonar/saved-projects/${proj.id}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        const data = (await res.json()) as {
          projects?: SavedSonarProjectWithVerification[];
        };
        if (Array.isArray(data.projects)) {
          setSavedSonarProjects(data.projects);
        }
        onNotify(`Perfil "${proj.projectKey}" removido.`, 'success');
      }
    } catch {
      onNotify('Erro ao remover perfil.', 'error');
    }
  };

  useEffect(() => {
    void checkDockerStatus();
    void loadHardwareProfile();
    void loadSavedSonarProjects();
  }, []);

  const copyToClipboard = (text: string, key: string) => {
    void navigator.clipboard.writeText(text);
    setCopiedKey(key);
    onNotify('Comando copiado para a área de transferência!', 'success');
    setTimeout(() => setCopiedKey(null), 2500);
  };

  const checkDockerStatus = async () => {
    setTestingDocker(true);
    try {
      const res = await fetch('/api/sonar/docker-status');
      const data = await res.json();
      setDockerStatus(data);
    } catch {
      onNotify('Não foi possível verificar o status do Docker.', 'error');
    } finally {
      setTestingDocker(false);
    }
  };

  const handleAutoStartDocker = async () => {
    setStartingDocker(true);
    try {
      const res = await fetch('/api/sonar/docker-auto-start', { method: 'POST' });
      const data = await res.json();
      if (data.fallbackToNative) {
        onNotify(data.message, 'success');
      } else if (data.ok) {
        onNotify(data.message, 'success');
      } else {
        onNotify(data.message || 'Falha ao gerenciar container.', 'error');
      }
      await checkDockerStatus();
    } catch {
      onNotify('Erro ao solicitar inicialização automática do Docker.', 'error');
    } finally {
      setStartingDocker(false);
    }
  };

  const handleStopDocker = async () => {
    setStoppingDocker(true);
    try {
      const res = await fetch('/api/sonar/docker-stop', { method: 'POST' });
      const data = await res.json();
      if (data.ok) {
        onNotify(data.message, 'success');
      } else {
        onNotify(data.error || 'Falha ao pausar container.', 'error');
      }
      await checkDockerStatus();
    } catch {
      onNotify('Erro ao solicitar pausa do Docker.', 'error');
    } finally {
      setStoppingDocker(false);
    }
  };

  const handleQuickRunAnalysis = async () => {
    setRunningQuickAnalysis(true);
    try {
      const res = await fetch('/api/benchmark-runs/quick-run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (res.ok) {
        onNotify('Análise de 1 Clique iniciada com sucesso! Acompanhe o progresso no topo da tela.', 'success');
      } else {
        onNotify(data.error || 'Falha ao iniciar análise rápida.', 'error');
      }
    } catch {
      onNotify('Erro ao disparar análise rápida.', 'error');
    } finally {
      setRunningQuickAnalysis(false);
    }
  };

  const testDockerConnection = async () => {
    setTestingDocker(true);
    try {
      const res = await fetch('/api/sonar/test-connection', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          serverUrl: hostUrl,
          token: token !== 'squ_token_exemplo123456' ? token : undefined,
          mode: 'DOCKER',
        }),
      });
      const data = await res.json();
      if (data.httpReachable) {
        onNotify(`MqrBridge Docker conectado com sucesso! Latência: ${data.latencyMs}ms.`, 'success');
      } else {
        onNotify(
          data.errorMessage || 'MqrBridge Docker não respondeu. Certifique-se de que o container está em execução.',
          'error'
        );
      }
      void checkDockerStatus();
    } catch {
      onNotify('Falha na comunicação de rede com o MqrBridge.', 'error');
    } finally {
      setTestingDocker(false);
    }
  };

  const testCloudConnection = async () => {
    if (!cloudToken.trim()) {
      onNotify('Informe o token do Nuvem MQR para testar a conexão.', 'error');
      return;
    }
    setTestingCloud(true);
    setCloudResult(null);
    try {
      const res = await fetch('/api/sonar/test-cloud', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          organizationKey: cloudOrg,
          token: cloudToken,
        }),
      });
      const data = await res.json();
      if (data.httpReachable && data.authenticated) {
        setCloudResult({ ok: true, message: 'Autenticado com sucesso na API do Nuvem MQR!' });
        onNotify('Conexão com Nuvem MQR validada com sucesso!', 'success');
      } else {
        setCloudResult({
          ok: false,
          message: data.errorMessage || 'Falha ao autenticar no Nuvem MQR. Verifique seu token e organização.',
        });
        onNotify('Falha ao autenticar no Nuvem MQR.', 'error');
      }
    } catch {
      setCloudResult({ ok: false, message: 'Erro de rede ao conectar com sonarcloud.io' });
    } finally {
      setTestingCloud(false);
    }
  };

  const loadHardwareProfile = async () => {
    setLoadingHardware(true);
    try {
      const res = await fetch('/api/system/hardware-profile');
      const data = await res.json();
      setHardware(data);
    } catch {
      // Ignorar fallback
    } finally {
      setLoadingHardware(false);
    }
  };

  const handleUpdateHardwareMode = async (mode: 'ECONOMICAL' | 'BALANCED' | 'TURBO_MAX') => {
    if (!hardware) return;
    setSavingHardware(true);
    try {
      const res = await fetch('/api/system/hardware-profile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ performanceMode: mode }),
      });
      const updated = await res.json();
      setHardware(updated);
      onNotify(`Perfil de hardware atualizado para ${mode}!`, 'success');
    } catch {
      onNotify('Erro ao atualizar perfil de hardware.', 'error');
    } finally {
      setSavingHardware(false);
    }
  };

  const handleUpdateThreads = async (threads: number) => {
    if (!hardware) return;
    try {
      const res = await fetch('/api/system/hardware-profile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ activeThreadsLimit: threads }),
      });
      const updated = await res.json();
      setHardware(updated);
    } catch {
      // fallback
    }
  };

  // Generated CLI commands based on ecosystem
  const cleanKey = projectKey.trim() || 'MEU_PROJETO';
  const cleanHost = hostUrl.trim() || 'http://localhost:9000';
  const cleanToken = token.trim() || 'SEU_TOKEN';

  const commandsMap = {
    nodejs: {
      install: 'npm install -D mqr-bridge-scanner',
      run: `npx sonar-scanner -Dsonar.projectKey=${cleanKey} -Dsonar.host.url=${cleanHost} -Dsonar.login=${cleanToken}`,
      desc: 'Para projetos Node.js / TypeScript: instala o scanner e executa a análise local enviando os relatórios.',
    },
    maven: {
      install: null,
      run: `mvn clean verify sonar:sonar -Dsonar.projectKey=${cleanKey} -Dsonar.host.url=${cleanHost} -Dsonar.login=${cleanToken}`,
      desc: 'Para projetos Java com Maven: executa compilação, testes e o plugin oficial sonar-maven-plugin.',
    },
    gradle: {
      install: null,
      run: `./gradlew sonar -Dsonar.projectKey=${cleanKey} -Dsonar.host.url=${cleanHost} -Dsonar.login=${cleanToken}`,
      desc: 'Para projetos Gradle: aciona a task sonar no Gradle com os parâmetros de conexão.',
    },
    dotnet: {
      install: 'dotnet tool install --global dotnet-sonarscanner',
      run: `dotnet-sonarscanner begin /k:"${cleanKey}" /d:sonar.host.url="${cleanHost}" /d:sonar.login="${cleanToken}" && dotnet build && dotnet-sonarscanner end /d:sonar.login="${cleanToken}"`,
      desc: 'Para projetos .NET / C#: envolve a compilação com o coletor do SonarScanner e publica métricas.',
    },
    cli: {
      install: null,
      run: `sonar-scanner -Dsonar.projectKey=${cleanKey} -Dsonar.host.url=${cleanHost} -Dsonar.login=${cleanToken}`,
      desc: 'Executa diretamente o binário global sonar-scanner instalado no sistema operacional.',
    },
  };

  const dockerCommand =
    'docker run -d --name mqr-bridge -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true -p 9000:9000 mqr-bridge:latest';

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-[#31d6c4]/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="flex flex-col sm:flex-row sm:items-center gap-4">
            <HairlineAnimatedFigure
              type="router"
              variant="hero"
              width={160}
              height={126}
              active={true}
              scanning={testingDocker || testingCloud || runningQuickAnalysis}
              accentColor="#38bdf8"
            />
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-[#31d6c4] tracking-wider uppercase">
                <Server className="w-4 h-4" />
                Sonar Hub Oficial &amp; Motor Windows Multi-Core
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">
                MqrBridge Local (Docker) vs Nuvem MQR (Nuvem)
              </h1>
              <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
                Execute a análise de código do MqrBridge via container oficial Docker sem necessidade de baixar zips pesados
                na máquina física, conecte ao Nuvem MQR na nuvem e utilize o poder multithread dos núcleos do seu processador.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              onClick={() => setActiveTab('hardware')}
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg transition-colors cursor-pointer"
            >
              <Cpu className="w-4 h-4 text-[#31d6c4]" />
              <span className="tabular-nums">
                {hardware ? `${hardware.activeThreadsLimit}/${hardware.totalLogicalCores} Threads Ativas` : 'Hardware Local'}
              </span>
            </button>
            <a
              href="http://localhost:9000"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] rounded-lg transition-colors"
            >
              <ExternalLink className="w-4 h-4" />
              Abrir Painel :9000
            </a>
          </div>
        </div>

        {/* Tab Navigation (Zero Pill Discipline - Interactive Filter Tabs) */}
        <div className="flex items-center gap-1 border-t border-slate-800 mt-6 pt-4 overflow-x-auto">
          <button
            onClick={() => setActiveTab('docker')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-colors cursor-pointer whitespace-nowrap ${
              activeTab === 'docker'
                ? 'bg-slate-800 text-[#31d6c4] shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Server className="w-4 h-4" />
            Opção A: MqrBridge Local (Docker)
          </button>
          <button
            onClick={() => setActiveTab('cloud')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-colors cursor-pointer whitespace-nowrap ${
              activeTab === 'cloud'
                ? 'bg-slate-800 text-[#31d6c4] shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Cloud className="w-4 h-4" />
            Opção B: Nuvem MQR (Nuvem)
          </button>
          <button
            onClick={() => setActiveTab('scanner')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-colors cursor-pointer whitespace-nowrap ${
              activeTab === 'scanner'
                ? 'bg-slate-800 text-[#31d6c4] shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Terminal className="w-4 h-4" />
            Gerador Scanner CLI MQR
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('hardware')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition-colors cursor-pointer whitespace-nowrap ${
              activeTab === 'hardware'
                ? 'bg-slate-800 text-[#31d6c4] shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Zap className="w-4 h-4" />
            Hardware & Executável Windows (.exe)
          </button>
        </div>
      </div>

      {/* ESPECIFICAÇÃO 2: Meus Projetos Servidor MQR / Nuvem MQR — Download 1-Clique de Relatório JSON & Monitor de Validade de Token */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-[#31d6c4]/15 text-[#31d6c4] border border-[#31d6c4]/30">
                EXPORTADOR DIRETO NUVEM MQR / SERVIDOR MQR
              </span>
              <span className="px-2.5 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300">
                Análise Completa: Quality Gate · Métricas MQR · Hotspots · Issues Paginadas
              </span>
            </div>
            <h2 className="text-lg font-bold text-white">
              Meus Projetos Servidor MQR / Nuvem MQR — Download 1-Clique de Relatório JSON
            </h2>
            <p className="text-xs text-slate-400">
              Cadastre seus projetos (`Project Key`, `Organization`, `Bearer Token`) para baixar relatórios JSON completos (Quality Gate, 39 Métricas, Security Hotspots, Componentes, Regras e Issues paginadas) ou gerar o script `.PS1` integral.
            </p>
          </div>

          <button
            type="button"
            onClick={() => {
              setEditingProfileId(null);
              setProfName('');
              setProfPlatform('SONARCLOUD');
              setProfServerUrl('');
              setProfOrganization('');
              setProfProjectKey('');
              setProfToken('');
              setProfValidityPolicy(90);
              setProfCustomExpiresAt('');
            }}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-bold border border-[#31d6c4]/40 text-[#31d6c4] hover:bg-[#31d6c4]/10 transition-colors cursor-pointer shrink-0"
          >
            <PlusCircle className="w-4 h-4" />
            Limpar Campos / Novo Projeto
          </button>
        </div>

        {/* Guia Passo a Passo de Token, Organization e Project Key (Retraído por padrão) */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/60 overflow-hidden">
          <button
            type="button"
            onClick={() => setIsHelpGuideOpen((prev) => !prev)}
            className="w-full px-5 py-3.5 flex items-center justify-between text-left bg-slate-900/60 hover:bg-slate-900 transition-colors cursor-pointer"
          >
            <div className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full bg-[#31d6c4]" />
              <span className="text-xs font-bold text-white">
                Guia Rápido: Onde encontrar Token, Organization e Project Key no Nuvem MQR?
              </span>
            </div>
            <span className="text-xs font-mono text-[#31d6c4]">
              {isHelpGuideOpen ? 'Ocultar Guia ▲' : 'Ver Passo a Passo ▼'}
            </span>
          </button>

          {isHelpGuideOpen && (
            <div className="p-5 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs text-slate-300 border-t border-slate-800 bg-slate-950/80">
              <div className="space-y-1.5 p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
                <div className="font-bold text-[#31d6c4] flex items-center gap-1.5">
                  <span>1. Bearer Token</span>
                </div>
                <p className="text-slate-400 leading-relaxed text-[11px]">
                  No Nuvem MQR (<a href="https://sonarcloud.io" target="_blank" rel="noreferrer" className="text-[#31d6c4] hover:underline">sonarcloud.io</a>), clique no seu <strong>avatar no canto superior direito</strong> → <strong>My Account</strong> → aba <strong>Security</strong> → em <em>Generate Tokens</em>, insira um nome (ex.: <code className="text-white">winhood-cli</code>) e clique em <strong>Generate</strong>.
                </p>
              </div>

              <div className="space-y-1.5 p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
                <div className="font-bold text-[#31d6c4] flex items-center gap-1.5">
                  <span>2. Organization Key</span>
                </div>
                <p className="text-slate-400 leading-relaxed text-[11px]">
                  Acesse o menu de organizações no topo direito (<strong>My Organizations</strong>) e copie a <strong>Key</strong> oficial exibida abaixo do nome da organização (ex.: <code className="text-white">lilnavahoods</code>).
                </p>
              </div>

              <div className="space-y-1.5 p-3 rounded-lg bg-slate-900/60 border border-slate-800/80">
                <div className="font-bold text-[#31d6c4] flex items-center gap-1.5">
                  <span>3. Project Key</span>
                </div>
                <p className="text-slate-400 leading-relaxed text-[11px]">
                  Abra seu projeto no Nuvem MQR → menu lateral inferior esquerdo <strong>Information</strong> → copie o campo <strong>Project Key</strong> exato (ex.: <code className="text-white">LilNavaHoods_Winhood-Benchmarking</code>).
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Formulário de Configuração & Validade do Token */}
        <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span className="text-xs font-bold text-slate-200 flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-[#31d6c4]" />
              {editingProfileId
                ? `Configurar / Atualizar Projeto Selecionado (${profProjectKey || 'Projeto'})`
                : 'Extração 1-Clique & Configuração do Nuvem MQR'}
            </span>
            <div className="flex items-center gap-3">
              {vaultStatus?.hasToken && (
                <span className="px-2.5 py-1 rounded text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  Cofre Ativo: Token Gravado com Sucesso
                </span>
              )}
              <span className="text-[11px] font-mono text-slate-400">
                Criptografia em Repouso: AES-256-GCM
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label
                htmlFor="sonar-prof-name"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Nome de Exibição do Projeto
              </label>
              <input
                id="sonar-prof-name"
                type="text"
                value={profName}
                onChange={(e) => setProfName(e.target.value)}
                placeholder="Ex.: WinHood Benchmarking Oficial"
                className="w-full rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-white focus:outline-none focus:border-[#31d6c4]"
              />
            </div>

            <div>
              <label
                htmlFor="sonar-prof-org"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Organization (`sonar.organization`)
              </label>
              <input
                id="sonar-prof-org"
                type="text"
                value={profOrganization}
                onChange={(e) => setProfOrganization(e.target.value)}
                placeholder="lilnavahoods"
                className="w-full rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-[#31d6c4]"
              />
            </div>

            <div>
              <label
                htmlFor="sonar-prof-key"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Project Key (`sonar.projectKey`)
              </label>
              <input
                id="sonar-prof-key"
                type="text"
                value={profProjectKey}
                onChange={(e) => setProfProjectKey(e.target.value)}
                placeholder="LilNavaHoods_Winhood-Benchmarking"
                className="w-full rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-[#31d6c4]"
              />
            </div>

            <div>
              <label
                htmlFor="sonar-prof-platform"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Plataforma &amp; URL do Servidor
              </label>
              <div className="flex gap-2">
                <select
                  id="sonar-prof-platform"
                  value={profPlatform}
                  onChange={(e) => {
                    const nextPlat = e.target.value as 'SONARCLOUD' | 'MQR_BRIDGE_SERVER';
                    setProfPlatform(nextPlat);
                  }}
                  className="rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-2 text-xs text-white focus:outline-none focus:border-[#31d6c4]"
                >
                  <option value="SONARCLOUD">Nuvem MQR</option>
                  <option value="MQR_BRIDGE_SERVER">MqrBridge Server</option>
                </select>
                <input
                  id="sonar-prof-url"
                  aria-label="URL do Servidor Sonar"
                  type="text"
                  value={profServerUrl}
                  onChange={(e) => setProfServerUrl(e.target.value)}
                  placeholder={
                    profPlatform === 'SONARCLOUD'
                      ? 'https://sonarcloud.io'
                      : 'http://localhost:9000'
                  }
                  className="flex-1 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-[#31d6c4]"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="sonar-prof-token"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Bearer Token (`SONAR_TOKEN`)
              </label>
              <div className="relative flex items-center">
                <input
                  id="sonar-prof-token"
                  type={showProfToken ? 'text' : 'password'}
                  value={profToken}
                  onChange={(e) => setProfToken(e.target.value)}
                  placeholder="Cole seu token do Nuvem MQR / Servidor MQR..."
                  className="w-full rounded-lg border border-slate-800 bg-slate-900 pl-3 pr-9 py-2 text-xs font-mono text-white focus:outline-none focus:border-[#31d6c4]"
                />
                <button
                  type="button"
                  onClick={() => setShowProfToken((prev) => !prev)}
                  className="absolute right-2.5 text-slate-400 hover:text-slate-200 cursor-pointer"
                  title={showProfToken ? 'Ocultar Token' : 'Mostrar Token'}
                >
                  {showProfToken ? (
                    <EyeOff className="w-3.5 h-3.5" />
                  ) : (
                    <Eye className="w-3.5 h-3.5" />
                  )}
                </button>
              </div>
            </div>

            <div>
              <label
                htmlFor="sonar-prof-validity"
                className="block text-xs font-semibold text-slate-300 mb-1"
              >
                Prazo de Validade do Token
              </label>
              <div className="flex gap-2">
                <select
                  id="sonar-prof-validity"
                  value={String(profValidityPolicy)}
                  onChange={(e) => {
                    const val = e.target.value;
                    if (val === '30' || val === '60' || val === '90') {
                      setProfValidityPolicy(Number(val) as 30 | 60 | 90);
                    } else if (val === 'CUSTOM') {
                      setProfValidityPolicy('CUSTOM');
                    } else {
                      setProfValidityPolicy('NO_EXPIRATION');
                    }
                  }}
                  className="flex-1 rounded-lg border border-slate-800 bg-slate-900 px-3 py-2 text-xs text-white focus:outline-none focus:border-[#31d6c4]"
                >
                  <option value="30">Expira em 30 dias</option>
                  <option value="60">Expira em 60 dias</option>
                  <option value="90">Expira em 90 dias (Padrão Sonar)</option>
                  <option value="NO_EXPIRATION">Sem Expiração</option>
                  <option value="CUSTOM">Data Personalizada</option>
                </select>
                {profValidityPolicy === 'CUSTOM' && (
                  <input
                    id="sonar-prof-custom-date"
                    aria-label="Data personalizada de expiração do token"
                    type="date"
                    value={profCustomExpiresAt}
                    onChange={(e) => setProfCustomExpiresAt(e.target.value)}
                    className="rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-2 text-xs font-mono text-white focus:outline-none focus:border-[#31d6c4]"
                  />
                )}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
            <span className="text-[11px] text-slate-400">
              Preencha os campos para baixar o JSON completo do Nuvem MQR ou salvar o projeto com segurança no cofre criptografado.
            </span>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={isExtractingDirect}
                onClick={() => void handleDirectOneClickExtract()}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-50 shadow-sm"
              >
                <Download className="w-4 h-4" />
                {isExtractingDirect ? 'Extraindo e Sincronizando...' : 'Extrair JSON Completo (1-Clique)'}
              </button>
              <button
                type="button"
                disabled={savingProfile}
                onClick={() => void handleSaveSonarProjectProfile()}
                className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-semibold border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors cursor-pointer disabled:opacity-50"
              >
                <ShieldCheck className="w-4 h-4 text-[#31d6c4]" />
                {savingProfile ? 'Salvando...' : 'Salvar no Cofre Local'}
              </button>
            </div>
          </div>
        </div>

        {/* Lista de Cards dos Projetos Sonar Salvos */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {loadingSavedProjects && savedSonarProjects.length === 0 ? (
            <div className="text-xs text-slate-400 font-mono p-4">
              Carregando projetos Sonar salvos...
            </div>
          ) : savedSonarProjects.length === 0 ? (
            <div className="col-span-full rounded-xl border border-dashed border-slate-800 bg-slate-950/40 p-6 text-center space-y-1.5">
              <div className="text-xs font-semibold text-slate-300">
                Nenhum projeto Nuvem MQR / MqrBridge cadastrado no momento
              </div>
              <p className="text-xs text-slate-400">
                Preencha os campos em branco acima com seu <code className="text-slate-200 font-mono">Project Key</code>, <code className="text-slate-200 font-mono">Organization</code> e <code className="text-slate-200 font-mono">Bearer Token</code> e clique em <strong className="text-slate-200">Salvar Perfil de Projeto</strong>.
              </p>
            </div>
          ) : (
            savedSonarProjects.map((proj) => {
              const ver = proj.tokenVerification;
              const statusLabel = ver?.statusLabel || 'NOT_CONFIGURED';

              let badgeClasses =
                'bg-slate-800 text-slate-300 border-slate-700';
              if (statusLabel === 'VALID_ACTIVE' || statusLabel === 'NO_EXPIRATION') {
                badgeClasses =
                  'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
              } else if (statusLabel === 'EXPIRING_SOON') {
                badgeClasses =
                  'bg-amber-500/15 text-amber-400 border-amber-500/30';
              } else if (statusLabel === 'EXPIRED' || statusLabel === 'INVALID_TOKEN') {
                badgeClasses =
                  'bg-rose-500/15 text-rose-400 border-rose-500/30';
              }

              return (
                <div
                  key={proj.id}
                  className={`rounded-xl border p-5 space-y-4 transition-colors ${
                    editingProfileId === proj.id
                      ? 'border-[#31d6c4]/60 bg-slate-950'
                      : 'border-slate-800 bg-slate-950/50 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-sm font-bold text-white">
                          {proj.name}
                        </h3>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#31d6c4]/15 text-[#31d6c4] border border-[#31d6c4]/30">
                          {proj.platform}
                        </span>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-3 text-xs font-mono text-slate-400">
                        <span>
                          ProjectKey: <strong className="text-slate-200">{proj.projectKey}</strong>
                        </span>
                        {proj.organization && (
                          <span>
                            Org: <strong className="text-slate-200">{proj.organization}</strong>
                          </span>
                        )}
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleSelectProfileForEdit(proj)}
                      className="px-2.5 py-1 rounded text-[11px] font-semibold border border-slate-700 text-slate-300 hover:bg-slate-800 cursor-pointer shrink-0"
                    >
                      {proj.hasToken ? 'Editar / Trocar Token' : 'Configurar Token'}
                    </button>
                  </div>

                  {/* Indicador Visual de Validade Restante do Token */}
                  <div
                    className={`rounded-lg border px-3.5 py-2.5 flex items-center justify-between gap-3 text-xs ${badgeClasses}`}
                  >
                    <div className="flex items-center gap-2">
                      {statusLabel === 'VALID_ACTIVE' ||
                      statusLabel === 'NO_EXPIRATION' ? (
                        <CheckCircle2 className="w-4 h-4 shrink-0" />
                      ) : statusLabel === 'EXPIRING_SOON' ? (
                        <Clock className="w-4 h-4 shrink-0" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 shrink-0" />
                      )}
                      <div>
                        <div className="font-semibold">
                          {ver?.message ||
                            'Token não configurado — cole seu Bearer Token acima'}
                        </div>
                        <div className="text-[11px] opacity-80 font-mono mt-0.5">
                          Token Mascarado: {proj.maskedToken}
                          {proj.lastExportedAt &&
                            ` · Última Exportação: ${proj.lastExportedIssuesCount ?? 0} issues em ${new Date(
                              proj.lastExportedAt
                            ).toLocaleString('pt-BR')}`}
                        </div>
                      </div>
                    </div>

                    {ver?.remainingDays !== null &&
                      ver?.remainingDays !== undefined && (
                        <div className="text-right font-mono shrink-0">
                          <div className="text-sm font-bold">
                            {ver.remainingDays}d {ver.remainingHours ?? 0}h
                          </div>
                          <div className="text-[10px] opacity-75">restantes</div>
                        </div>
                      )}
                  </div>

                  {/* 4 Botões de Ação do Card */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        disabled={exportingJsonId === proj.id}
                        onClick={() => void handleDownloadSonarJsonReport(proj)}
                        className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-50"
                      >
                        <Download className="w-3.5 h-3.5" />
                        {exportingJsonId === proj.id
                          ? 'Baixando Análise Completa...'
                          : 'Baixar Relatório JSON Agora'}
                      </button>

                      <button
                        type="button"
                        disabled={exportingPs1Id === proj.id}
                        onClick={() => void handleDownloadSonarPs1Script(proj)}
                        className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors cursor-pointer disabled:opacity-50"
                      >
                        <FileCode2 className="w-3.5 h-3.5 text-[#31d6c4]" />
                        Baixar Script .PS1
                      </button>

                      <button
                        type="button"
                        disabled={verifyingProjectId === proj.id}
                        onClick={() => void handleVerifyProjectToken(proj.id)}
                        className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold border border-slate-700 bg-slate-900 text-slate-200 hover:bg-slate-800 transition-colors cursor-pointer disabled:opacity-50"
                      >
                        <RefreshCw
                          className={`w-3.5 h-3.5 ${
                            verifyingProjectId === proj.id ? 'animate-spin' : ''
                          }`}
                        />
                        Verificar Token
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={() => void handleDeleteSavedProject(proj)}
                      className="inline-flex items-center gap-1 px-2.5 py-2 rounded-lg text-xs font-semibold text-rose-400 hover:bg-rose-500/10 transition-colors cursor-pointer"
                      title="Remover Perfil"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      Remover
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* PAINEL DE METODOLOGIA OFICIAL SONARCLOUD: MQR vs Standard, Quality Gate, Overall vs New Code, Cobertura Separada & Hotspots */}
      {methodologySummary && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-[#31d6c4]/15 text-[#31d6c4] border border-[#31d6c4]/30">
                  METODOLOGIA OFICIAL SONARCLOUD: {methodologySummary.qualityModelMode}
                </span>
                <span className="px-2.5 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300">
                  Quality Profile: {methodologySummary.qualityProfileVerification.profileName} ({methodologySummary.qualityProfileVerification.verificationState})
                </span>
                <span className="px-2.5 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-300">
                  Paginação Issues: {methodologySummary.paginationSummary.issuesPagination.state || methodologySummary.paginationSummary.issuesPagination.completeness || methodologySummary.paginationSummary.issuesPagination.status} ({methodologySummary.paginationSummary.issuesPagination.fetchedRecords ?? methodologySummary.paginationSummary.issuesPagination.totalReceived}/{methodologySummary.paginationSummary.issuesPagination.totalReported ?? methodologySummary.paginationSummary.issuesPagination.totalExpected ?? 0})
                </span>
              </div>
              <h2 className="text-lg font-bold text-white">
                Governança &amp; Rastreabilidade Metodológica Nuvem MQR vs WinHood
              </h2>
              <p className="text-xs text-slate-400">
                Separação estrita entre métricas oficiais retornadas pela Web API do Nuvem MQR (`SONARCLOUD_OFFICIAL_API`), métricas ausentes (`NOT_MEASURED`) e pontuações calculadas pelo motor nativo do WinHood (`WINHOOD_CALCULATED`).
              </p>
            </div>
            <button
              type="button"
              onClick={() => void loadMethodologySummary()}
              disabled={loadingMethodology}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-700 bg-slate-950 text-slate-200 hover:border-[#31d6c4] transition-colors cursor-pointer shrink-0"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingMethodology ? 'animate-spin' : ''}`} />
              Atualizar Governança
            </button>
          </div>

          {/* 1. Separação Estrita: Nuvem MQR Nativo vs WinHood Calculado */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-[#31d6c4] font-mono">
                  ORIGEM: {methodologySummary.scoreSeparation.nativeSonarMetrics.source}
                </span>
                <span className="text-[11px] font-mono text-slate-400">
                  Quality Gate: {methodologySummary.qualityGate.status}
                </span>
              </div>
              <div className="text-sm font-bold text-white">
                Ratings Oficiais Nativos do Nuvem MQR (Escala A–E)
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-400">Reliability</div>
                  <div className="text-sm font-bold text-white mt-0.5">
                    {methodologySummary.scoreSeparation.nativeSonarMetrics.reliabilityRating}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-400">Security</div>
                  <div className="text-sm font-bold text-white mt-0.5">
                    {methodologySummary.scoreSeparation.nativeSonarMetrics.securityRating}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-400">Maintainability</div>
                  <div className="text-sm font-bold text-white mt-0.5">
                    {methodologySummary.scoreSeparation.nativeSonarMetrics.maintainabilityRating}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-400">Hotspot Review</div>
                  <div className="text-sm font-bold text-white mt-0.5">
                    {methodologySummary.scoreSeparation.nativeSonarMetrics.securityReviewRating}
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-amber-400 font-mono">
                  ORIGEM: {methodologySummary.scoreSeparation.winhoodCalculatedScore.source}
                </span>
                <span className="text-[11px] font-mono text-slate-400">
                  Algoritmo v{methodologySummary.scoreSeparation.winhoodCalculatedScore.algorithmVersion}
                </span>
              </div>
              <div className="text-sm font-bold text-white">
                Pontuação Determinística Calculada pelo WinHood (Escala 0.00–5.00)
              </div>
              <div className="grid grid-cols-3 gap-2 text-xs font-mono">
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-400">Overall Score</div>
                  <div className="text-sm font-bold text-[#31d6c4] mt-0.5">
                    {methodologySummary.scoreSeparation.winhoodCalculatedScore.overallScore !== null
                      ? `${methodologySummary.scoreSeparation.winhoodCalculatedScore.overallScore.toFixed(2)} / 5.00`
                      : 'NOT_MEASURED'}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-400">Security Score</div>
                  <div className="text-sm font-bold text-white mt-0.5">
                    {methodologySummary.scoreSeparation.winhoodCalculatedScore.securityScore !== null
                      ? `${methodologySummary.scoreSeparation.winhoodCalculatedScore.securityScore.toFixed(2)} / 5.00`
                      : 'NOT_MEASURED'}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                  <div className="text-[10px] text-slate-400">Quality Score</div>
                  <div className="text-sm font-bold text-white mt-0.5">
                    {methodologySummary.scoreSeparation.winhoodCalculatedScore.qualityScore !== null
                      ? `${methodologySummary.scoreSeparation.winhoodCalculatedScore.qualityScore.toFixed(2)} / 5.00`
                      : 'NOT_MEASURED'}
                  </div>
                </div>
              </div>
              <div className="text-[11px] text-slate-400">
                {methodologySummary.scoreSeparation.winhoodCalculatedScore.note}
              </div>
            </div>
          </div>

          {/* 2. Quality Gate Oficial, Condições Individuais e Fudge Factor */}
          <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-bold text-white">
                  Quality Gate &amp; Condições Individuais ({methodologySummary.qualityGate.displayLabel})
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  {methodologySummary.qualityGate.explanationSummary}
                </p>
              </div>
              <div className="text-xs font-mono text-slate-300">
                Fudge Factor: <strong className="text-[#31d6c4]">{methodologySummary.qualityGate.fudgeFactorStatus || 'UNKNOWN'}</strong>
              </div>
            </div>

            {methodologySummary.qualityGate.fudgeFactorExplanation && (
              <div className="text-[11px] font-mono text-slate-400 bg-slate-900/80 border border-slate-800 rounded px-3 py-2">
                {methodologySummary.qualityGate.fudgeFactorExplanation}
              </div>
            )}

            {methodologySummary.qualityGate.conditions.length === 0 ? (
              <div className="text-xs font-mono text-slate-400 p-3 rounded border border-slate-800 bg-slate-900/40">
                Nenhuma condição individual retornada pela API do Nuvem MQR (`status: {methodologySummary.qualityGate.status}`).
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2 pr-3">Condição</th>
                      <th className="py-2 px-3">Escopo</th>
                      <th className="py-2 px-3">Valor</th>
                      <th className="py-2 px-3">Limite</th>
                      <th className="py-2 px-3">Estado</th>
                      <th className="py-2 pl-3">Justificativa</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {methodologySummary.qualityGate.conditions.map((cond, idx) => (
                      <tr key={`${cond.metricKey}-${idx}`}>
                        <td className="py-2 pr-3 text-white font-semibold">{cond.metricKey}</td>
                        <td className="py-2 px-3 text-slate-300">{cond.scope || 'OVERALL_CODE'}</td>
                        <td className="py-2 px-3 text-slate-200">{cond.actualValue}</td>
                        <td className="py-2 px-3 text-slate-400">
                          {cond.comparator} {cond.errorThreshold}
                        </td>
                        <td className="py-2 px-3">
                          <span
                            className={
                              cond.status === 'OK'
                                ? 'text-emerald-400 font-bold'
                                : cond.status === 'ERROR'
                                  ? 'text-rose-400 font-bold'
                                  : 'text-amber-400 font-bold'
                            }
                          >
                            {cond.status}
                          </span>
                        </td>
                        <td className="py-2 pl-3 font-sans text-slate-300">
                          {cond.reasonText || '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* 3. Overall Code vs New Code & Cobertura Separada & Hotspots Breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Overall vs New Code */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 space-y-2.5">
              <div className="text-xs font-bold text-white uppercase tracking-wider">
                Overall Code vs New Code (Clean as You Code)
              </div>
              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">Bugs (Overall / New):</span>
                  <span className="text-slate-200">
                    {methodologySummary.measures.metrics.bugs ?? 'NOT_MEASURED'} /{' '}
                    {methodologySummary.measures.newCode?.newBugs ?? 'NOT_MEASURED'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Vulnerabilities (Overall / New):</span>
                  <span className="text-slate-200">
                    {methodologySummary.measures.metrics.vulnerabilities ?? 'NOT_MEASURED'} /{' '}
                    {methodologySummary.measures.newCode?.newVulnerabilities ?? 'NOT_MEASURED'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Code Smells (Overall / New):</span>
                  <span className="text-slate-200">
                    {methodologySummary.measures.metrics.codeSmells ?? 'NOT_MEASURED'} /{' '}
                    {methodologySummary.measures.newCode?.newCodeSmells ?? 'NOT_MEASURED'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Duplicação % (Overall / New):</span>
                  <span className="text-slate-200">
                    {methodologySummary.measures.metrics.duplicatedLinesDensityPercent !== null
                      ? `${methodologySummary.measures.metrics.duplicatedLinesDensityPercent}%`
                      : 'NOT_MEASURED'}{' '}
                    /{' '}
                    {methodologySummary.measures.newCode?.newDuplicatedLinesDensityPercent !== null &&
                    methodologySummary.measures.newCode?.newDuplicatedLinesDensityPercent !== undefined
                      ? `${methodologySummary.measures.newCode.newDuplicatedLinesDensityPercent}%`
                      : 'NOT_MEASURED'}
                  </span>
                </div>
              </div>
            </div>

            {/* Cobertura Separada */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 space-y-2.5">
              <div className="text-xs font-bold text-white uppercase tracking-wider">
                Métricas de Cobertura Separadas (Sem Equivalência Artificial)
              </div>
              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">Coverage Geral / New:</span>
                  <span className="text-slate-200">
                    {methodologySummary.measures.metrics.coveragePercent !== null
                      ? `${methodologySummary.measures.metrics.coveragePercent}%`
                      : 'NOT_MEASURED'}{' '}
                    /{' '}
                    {methodologySummary.measures.newCode?.newCoveragePercent !== null &&
                    methodologySummary.measures.newCode?.newCoveragePercent !== undefined
                      ? `${methodologySummary.measures.newCode.newCoveragePercent}%`
                      : 'NOT_MEASURED'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Line Coverage:</span>
                  <span className="text-slate-200">
                    {methodologySummary.measures.metrics.lineCoveragePercent !== null &&
                    methodologySummary.measures.metrics.lineCoveragePercent !== undefined
                      ? `${methodologySummary.measures.metrics.lineCoveragePercent}%`
                      : 'NOT_MEASURED'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Branch Coverage:</span>
                  <span className="text-slate-200">
                    {methodologySummary.measures.metrics.branchCoveragePercent !== null &&
                    methodologySummary.measures.metrics.branchCoveragePercent !== undefined
                      ? `${methodologySummary.measures.metrics.branchCoveragePercent}%`
                      : 'NOT_MEASURED'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Uncovered Lines / Conditions:</span>
                  <span className="text-slate-200">
                    {methodologySummary.measures.metrics.uncoveredLines ?? 'NOT_MEASURED'} /{' '}
                    {methodologySummary.measures.metrics.uncoveredConditions ?? 'NOT_MEASURED'}
                  </span>
                </div>
              </div>
            </div>

            {/* Security Hotspots Breakdown */}
            <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4 space-y-2.5">
              <div className="text-xs font-bold text-white uppercase tracking-wider">
                Security Hotspots Breakdown ({methodologySummary.hotspotsBreakdown.measurementState})
              </div>
              <div className="space-y-1.5 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">Identificados / Não Revisados:</span>
                  <span className="text-slate-200">
                    {methodologySummary.hotspotsBreakdown.totalIdentified ?? 'NOT_MEASURED'} /{' '}
                    {methodologySummary.hotspotsBreakdown.unreviewedCount ?? 'NOT_MEASURED'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Revisados (Safe / Fixed):</span>
                  <span className="text-slate-200">
                    {methodologySummary.hotspotsBreakdown.reviewedSafeCount ?? 'NOT_MEASURED'} /{' '}
                    {methodologySummary.hotspotsBreakdown.reviewedFixedCount ?? 'NOT_MEASURED'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Risco Aceito (Acknowledged):</span>
                  <span className="text-slate-200">
                    {methodologySummary.hotspotsBreakdown.acceptedRiskCount ?? 'NOT_MEASURED'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Percentual de Revisão:</span>
                  <span className="text-[#31d6c4] font-bold">
                    {methodologySummary.hotspotsBreakdown.reviewPercent !== null
                      ? `${methodologySummary.hotspotsBreakdown.reviewPercent}%`
                      : 'NOT_MEASURED'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 1: MqrBridge Local (Docker) */}
      {activeTab === 'docker' && (
        <div className="space-y-6">
          {/* Automatic Backend Control Card (Zero-Configuration & Auto Docker) */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 relative overflow-hidden">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-xs font-semibold text-[#31d6c4] tracking-wider uppercase">
                  <Zap className="w-4 h-4" />
                  Automação Total: O Backend cuida de tudo para você
                </div>
                <h2 className="text-lg font-bold text-white tracking-tight">
                  Servidor MqrBridge & Motor de Análise em 1 Clique
                </h2>
                <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
                  Você não precisa abrir terminais, baixar zips pesados nem saber comandos do Docker.
                  O backend gerencia o container do MqrBridge automaticamente ou ativa o motor nativo local de alta performance
                  sem que você precise se preocupar com infraestrutura.
                </p>
                <div className="flex items-center gap-2 pt-1 text-xs text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  <span>Fallback inteligente: Se não houver Docker na máquina, o motor nativo assume com nota 100% equivalente.</span>
                </div>
              </div>

              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 shrink-0">
                {!dockerStatus?.isReachable ? (
                  <button
                    onClick={handleAutoStartDocker}
                    disabled={startingDocker}
                    className="inline-flex items-center justify-center gap-2 px-5 py-3 rounded-lg text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer shadow-md disabled:opacity-50"
                  >
                    <Play className="w-4 h-4 fill-current" />
                    {startingDocker
                      ? 'Iniciando Container pelo Backend...'
                      : 'Iniciar MqrBridge Automaticamente (1 Clique)'}
                  </button>
                ) : (
                  <button
                    onClick={handleStopDocker}
                    disabled={stoppingDocker}
                    className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-xs font-bold bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/30 transition-colors cursor-pointer disabled:opacity-50"
                  >
                    {stoppingDocker ? 'Pausando...' : 'Pausar Container MqrBridge'}
                  </button>
                )}

                <button
                  onClick={handleQuickRunAnalysis}
                  disabled={runningQuickAnalysis}
                  className="inline-flex items-center justify-center gap-2 px-5 py-3 rounded-lg text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700 transition-colors cursor-pointer disabled:opacity-50"
                >
                  <ShieldCheck className="w-4 h-4 text-[#31d6c4]" />
                  {runningQuickAnalysis ? 'Disparando...' : 'Executar Análise de 1 Clique Agora'}
                </button>
              </div>
            </div>
          </div>

          {/* Status Box */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div
                  className={`w-3.5 h-3.5 rounded-full ${
                    dockerStatus?.isReachable ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'
                  }`}
                />
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    Status do MqrBridge em http://localhost:9000
                    <span className="text-xs text-slate-400 font-normal">
                      · {dockerStatus?.isReachable ? 'ONLINE (Pronto)' : 'OFFLINE (Aguardando container)'}
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {dockerStatus?.isReachable
                      ? `Conexão estabelecida com sucesso. Versão do Sonar: ${dockerStatus.version || 'Detectada'}. Latência: ${dockerStatus.latencyMs}ms.`
                      : 'O container MqrBridge não está ativo no momento. Clique no botão acima para iniciar automaticamente.'}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={testDockerConnection}
                  disabled={testingDocker}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg transition-colors cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${testingDocker ? 'animate-spin' : ''}`} />
                  Testar Conexão Local
                </button>
                <a
                  href="http://localhost:9000"
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] rounded-lg transition-colors"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  Acessar Painel Web
                </a>
              </div>
            </div>
          </div>

          {/* Step 1: Run Docker Container */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <span className="flex items-center justify-center w-6 h-6 rounded-full bg-[#31d6c4] text-slate-950 text-xs font-black">
                1
              </span>
              Suba o container oficial do MqrBridge no seu terminal
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              A forma mais rápida e limpa de rodar o servidor local do MqrBridge sem sujar o sistema operacional com
              instalações pesadas de JDK ou arquivos zip de centenas de megabytes é através do Docker:
            </p>

            <div className="relative group">
              <pre className="bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs text-[#31d6c4] overflow-x-auto whitespace-pre-wrap select-all">
                {dockerCommand}
              </pre>
              <button
                onClick={() => copyToClipboard(dockerCommand, 'docker-run')}
                className="absolute top-3 right-3 inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors cursor-pointer"
              >
                {copiedKey === 'docker-run' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    Copiado!
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    Copiar
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Step 2, 3, 4 Steps Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2.5">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <span className="flex items-center justify-center w-6 h-6 rounded-full bg-slate-800 text-[#31d6c4] border border-slate-700 text-xs font-black">
                  2
                </span>
                Acesse o painel web
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Abra seu navegador em{' '}
                <a
                  href="http://localhost:9000"
                  target="_blank"
                  rel="noreferrer"
                  className="text-[#31d6c4] underline hover:text-[#28bfb0]"
                >
                  http://localhost:9000
                </a>
                . O MqrBridge leva cerca de 20 a 40 segundos para inicializar os serviços internos na primeira vez.
              </p>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2.5">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <span className="flex items-center justify-center w-6 h-6 rounded-full bg-slate-800 text-[#31d6c4] border border-slate-700 text-xs font-black">
                  3
                </span>
                Login Inicial
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Faça login com usuário <code className="text-slate-200 font-mono bg-slate-950 px-1 py-0.5 rounded">admin</code> e senha{' '}
                <code className="text-slate-200 font-mono bg-slate-950 px-1 py-0.5 rounded">admin</code>. O sistema solicitará que você defina uma nova senha no primeiro acesso.
              </p>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2.5">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <span className="flex items-center justify-center w-6 h-6 rounded-full bg-slate-800 text-[#31d6c4] border border-slate-700 text-xs font-black">
                  4
                </span>
                Crie o Projeto e Token
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Clique em <strong className="text-white">Create a local project</strong>, defina a chave do projeto (ex:{' '}
                <code className="text-slate-200 font-mono bg-slate-950 px-1 py-0.5 rounded">MEU_PROJETO</code>) e gere um Token de Acesso para alimentar o SonarScanner.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Nuvem MQR (Nuvem) */}
      {activeTab === 'cloud' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-2 text-base font-bold text-white">
              <Cloud className="w-5 h-5 text-[#31d6c4]" />
              Opção B: Nuvem MQR (100% em Nuvem - Sem Instalação Local)
            </div>
            <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
              Se você não quiser instalar nem rodar o Docker na sua máquina, utilize a versão oficial na nuvem
              (Nuvem MQR), ideal para integração contínua (CI/CD) direta com repositórios GitHub, GitLab e Bitbucket.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div className="border border-slate-800 bg-slate-950/60 rounded-lg p-4 space-y-2">
                <div className="text-xs font-bold text-white flex items-center gap-2">
                  <span className="w-5 h-5 rounded-full bg-[#31d6c4] text-slate-950 flex items-center justify-center text-xs font-bold">1</span>
                  Login com seu Git
                </div>
                <p className="text-xs text-slate-400">
                  Acesse <a href="https://sonarcloud.io" target="_blank" rel="noreferrer" className="text-[#31d6c4] underline">sonarcloud.io</a> e entre com sua conta do GitHub, GitLab ou Bitbucket.
                </p>
              </div>

              <div className="border border-slate-800 bg-slate-950/60 rounded-lg p-4 space-y-2">
                <div className="text-xs font-bold text-white flex items-center gap-2">
                  <span className="w-5 h-5 rounded-full bg-[#31d6c4] text-slate-950 flex items-center justify-center text-xs font-bold">2</span>
                  Importe o Repositório
                </div>
                <p className="text-xs text-slate-400">
                  Selecione os repositórios públicos ou privados da sua organização que deseja submeter à análise contínua.
                </p>
              </div>

              <div className="border border-slate-800 bg-slate-950/60 rounded-lg p-4 space-y-2">
                <div className="text-xs font-bold text-white flex items-center gap-2">
                  <span className="w-5 h-5 rounded-full bg-[#31d6c4] text-slate-950 flex items-center justify-center text-xs font-bold">3</span>
                  Análise Automática
                </div>
                <p className="text-xs text-slate-400">
                  O Nuvem MQR ativará a análise automática a cada novo commit e pull request sem necessidade de servidor local.
                </p>
              </div>
            </div>
          </div>

          {/* Test Nuvem MQR Token Form */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <h3 className="text-sm font-bold text-white">Vincular e Validar Credenciais do Nuvem MQR</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label
                  htmlFor="hub-cloud-org"
                  className="block text-xs font-medium text-slate-400 mb-1.5"
                >
                  Chave da Organização (Organization Key)
                </label>
                <input
                  id="hub-cloud-org"
                  type="text"
                  value={cloudOrg}
                  onChange={(e) => setCloudOrg(e.target.value)}
                  placeholder="ex: minha-empresa-github"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-white focus:outline-none focus:border-[#31d6c4] font-mono"
                />
              </div>

              <div>
                <label
                  htmlFor="hub-cloud-token"
                  className="block text-xs font-medium text-slate-400 mb-1.5"
                >
                  Token de Acesso Nuvem MQR
                </label>
                <input
                  id="hub-cloud-token"
                  type="password"
                  value={cloudToken}
                  onChange={(e) => setCloudToken(e.target.value)}
                  placeholder="Insira seu token gerado no Nuvem MQR My Account > Security"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3.5 py-2 text-xs text-white focus:outline-none focus:border-[#31d6c4] font-mono"
                />
              </div>
            </div>

            <div className="flex items-center justify-between pt-2">
              <button
                onClick={testCloudConnection}
                disabled={testingCloud}
                className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] rounded-lg transition-colors cursor-pointer disabled:opacity-50"
              >
                <ShieldCheck className="w-4 h-4" />
                {testingCloud ? 'Validando no Nuvem MQR...' : 'Testar Conexão Nuvem MQR'}
              </button>

              {cloudResult && (
                <div
                  className={`text-xs font-medium flex items-center gap-1.5 ${
                    cloudResult.ok ? 'text-emerald-400' : 'text-rose-400'
                  }`}
                >
                  {cloudResult.ok ? <Check className="w-4 h-4" /> : null}
                  {cloudResult.message}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: SonarScanner Generator */}
      {activeTab === 'scanner' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-[#31d6c4]" />
                  Como Rodar a Análise na sua Aplicação
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Envie os dados do seu código local para o servidor MqrBridge gerando o comando correspondente à stack do seu projeto.
                </p>
              </div>

              {/* Ecosystem Selector */}
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 overflow-x-auto">
                {(['nodejs', 'maven', 'gradle', 'dotnet', 'cli'] as const).map((eco) => (
                  <button
                    key={eco}
                    onClick={() => setScannerEcosystem(eco)}
                    className={`px-3 py-1.5 text-xs font-bold rounded-md transition-colors cursor-pointer ${
                      scannerEcosystem === eco
                        ? 'bg-[#31d6c4] text-slate-950 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {eco === 'nodejs'
                      ? 'Node.js'
                      : eco === 'maven'
                        ? 'Maven (Java)'
                        : eco === 'gradle'
                          ? 'Gradle'
                          : eco === 'dotnet'
                            ? '.NET'
                            : 'CLI Global'}
                  </button>
                ))}
              </div>
            </div>

            {/* Inputs for Custom Parameters */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              <div>
                <label
                  htmlFor="hub-scanner-project-key"
                  className="block text-xs font-medium text-slate-400 mb-1"
                >
                  Chave do Projeto (-Dsonar.projectKey)
                </label>
                <input
                  id="hub-scanner-project-key"
                  type="text"
                  value={projectKey}
                  onChange={(e) => setProjectKey(e.target.value)}
                  placeholder="Informe a chave do projeto..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-[#31d6c4]"
                />
              </div>

              <div>
                <label
                  htmlFor="hub-scanner-host-url"
                  className="block text-xs font-medium text-slate-400 mb-1"
                >
                  URL do Servidor (-Dsonar.host.url)
                </label>
                <input
                  id="hub-scanner-host-url"
                  type="text"
                  value={hostUrl}
                  onChange={(e) => setHostUrl(e.target.value)}
                  placeholder="http://localhost:9000"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-[#31d6c4]"
                />
              </div>

              <div>
                <label
                  htmlFor="hub-scanner-token"
                  className="block text-xs font-medium text-slate-400 mb-1"
                >
                  Token de Acesso (-Dsonar.login)
                </label>
                <input
                  id="hub-scanner-token"
                  type="password"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="Cole seu token de acesso..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white font-mono focus:outline-none focus:border-[#31d6c4]"
                />
              </div>
            </div>

            {/* Command Display */}
            <div className="space-y-4 pt-2">
              <p className="text-xs text-slate-400">{commandsMap[scannerEcosystem].desc}</p>

              {commandsMap[scannerEcosystem].install && (
                <div className="space-y-1.5">
                  <div className="text-xs font-semibold text-slate-300">Passo 1: Instalação do Scanner</div>
                  <div className="relative group">
                    <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-xs text-slate-200 select-all overflow-x-auto">
                      {commandsMap[scannerEcosystem].install}
                    </pre>
                    <button
                      onClick={() =>
                        copyToClipboard(commandsMap[scannerEcosystem].install!, 'install-cmd')
                      }
                      className="absolute top-2 right-2 inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 cursor-pointer"
                    >
                      {copiedKey === 'install-cmd' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                </div>
              )}

              <div className="space-y-1.5">
                <div className="text-xs font-semibold text-slate-300">
                  {commandsMap[scannerEcosystem].install ? 'Passo 2: Execução da Análise' : 'Comando de Execução'}
                </div>
                <div className="relative group">
                  <pre className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 font-mono text-xs text-[#31d6c4] select-all overflow-x-auto whitespace-pre-wrap">
                    {commandsMap[scannerEcosystem].run}
                  </pre>
                  <button
                    onClick={() => copyToClipboard(commandsMap[scannerEcosystem].run, 'run-cmd')}
                    className="absolute top-2.5 right-2.5 inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition-colors cursor-pointer"
                  >
                    {copiedKey === 'run-cmd' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        Copiado!
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        Copiar Comando
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: Hardware & Windows Executable */}
      {activeTab === 'hardware' && (
        <div className="space-y-6">
          {/* Hardware Telemetry Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <Cpu className="w-5 h-5 text-[#31d6c4]" />
                  Aproveitamento de Hardware & Testes Pesados
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Configure a utilização de múltiplos núcleos de CPU e alocação de memória RAM para executar
                  análises e benchmarks massivos na sua máquina física sem travamentos.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={loadHardwareProfile}
                  disabled={loadingHardware}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg transition-colors cursor-pointer"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loadingHardware ? 'animate-spin' : ''}`} />
                  Detectar Hardware
                </button>
              </div>
            </div>

            {/* Hardware KPI Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                <div className="text-xs text-slate-400">Processador Detectado</div>
                <div className="text-sm font-bold text-white mt-1 truncate" title={hardware?.cpuModel}>
                  {hardware?.cpuModel || 'CPU x86_64 / ARM'}
                </div>
                <div className="text-xs text-slate-500 mt-1">{hardware?.architecture} · {hardware?.platform}</div>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                <div className="text-xs text-slate-400">Núcleos Lógicos de CPU</div>
                <div className="text-2xl font-black text-[#31d6c4] tabular-nums mt-1">
                  {hardware?.totalLogicalCores ?? 8}
                </div>
                <div className="text-xs text-slate-500 mt-1">Cores disponíveis para threads</div>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                <div className="text-xs text-slate-400">Threads Ativas Alocadas</div>
                <div className="text-2xl font-black text-white tabular-nums mt-1">
                  {hardware?.activeThreadsLimit ?? 4}
                </div>
                <div className="text-xs text-slate-500 mt-1">
                  {Math.round(((hardware?.activeThreadsLimit ?? 4) / (hardware?.totalLogicalCores || 1)) * 100)}% da capacidade
                </div>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-lg p-4">
                <div className="text-xs text-slate-400">Memória RAM Livre / Total</div>
                <div className="text-sm font-bold text-white tabular-nums mt-1">
                  {hardware ? `${Math.round(hardware.freeMemoryMb / 1024)}GB / ${Math.round(hardware.totalMemoryMb / 1024)}GB` : 'N/D'}
                </div>
                <div className="text-xs text-slate-500 mt-1">Limite alocado: {hardware ? Math.round(hardware.memoryLimitMb / 1024) : 4}GB</div>
              </div>
            </div>

            {/* Performance Mode Selector */}
            <div className="space-y-3 pt-2">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Seletor de Modo de Intensidade de Processamento
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <button
                  type="button"
                  onClick={() => handleUpdateHardwareMode('ECONOMICAL')}
                  className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                    hardware?.performanceMode === 'ECONOMICAL'
                      ? 'bg-slate-800/80 border-[#31d6c4] ring-1 ring-[#31d6c4]'
                      : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">Econômico (Baixo Impacto)</span>
                    <span className="text-xs text-slate-400 tabular-nums">2 Cores</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    Ideal para computadores mais modestos ou quando você precisa continuar utilizando outras ferramentas pesadas simultaneamente.
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleUpdateHardwareMode('BALANCED')}
                  className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                    hardware?.performanceMode === 'BALANCED'
                      ? 'bg-slate-800/80 border-[#31d6c4] ring-1 ring-[#31d6c4]'
                      : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">Equilibrado (Recomendado)</span>
                    <span className="text-xs text-[#31d6c4] tabular-nums">75% Cores</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    Oferece alta taxa de análise para projetos médios mantendo a interface gráfica e o sistema operacionais fluidos.
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => handleUpdateHardwareMode('TURBO_MAX')}
                  className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                    hardware?.performanceMode === 'TURBO_MAX'
                      ? 'bg-slate-800/80 border-[#31d6c4] ring-1 ring-[#31d6c4]'
                      : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">Turbo / Máxima Performance</span>
                    <span className="text-xs text-amber-400 tabular-nums">100% Cores</span>
                  </div>
                  <p className="text-xs text-slate-400 mt-2">
                    Consome todo o poder da sua máquina para concluir análises em milhares de arquivos e testes pesados no menor tempo possível.
                  </p>
                </button>
              </div>
            </div>

            {/* Fine-Tuning Slider */}
            {hardware && (
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <div className="flex items-center justify-between text-xs text-slate-300">
                  <span>Ajuste Fino de Threads Concorrentes:</span>
                  <span className="font-bold text-[#31d6c4] tabular-nums">
                    {hardware.activeThreadsLimit} de {hardware.totalLogicalCores} núcleos
                  </span>
                </div>
                <input
                  type="range"
                  min="1"
                  max={hardware.totalLogicalCores}
                  value={hardware.activeThreadsLimit}
                  onChange={(e) => handleUpdateThreads(Number(e.target.value))}
                  className="w-full accent-[#31d6c4] cursor-pointer"
                />
              </div>
            )}
          </div>

          {/* Windows Desktop .EXE Packaging & Execution */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-2 text-base font-bold text-white">
              <Monitor className="w-5 h-5 text-[#31d6c4]" />
              Execução Nativa no Windows (.exe) e Instalador Desktop
            </div>
            <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
              Você pode executar o WinHood diretamente na sua máquina Windows com privilégio de CPU elevado e aceleração
              por GPU através dos scripts inclusos no repositório:
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
              <div className="border border-slate-800 bg-slate-950 rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-bold text-white flex items-center gap-2">
                    <HardDrive className="w-4 h-4 text-[#31d6c4]" />
                    1. Execução Imediata em 1 Clique (.bat)
                  </div>
                  <span className="text-xs text-slate-500 font-mono">scripts/windows/</span>
                </div>
                <p className="text-xs text-slate-400">
                  Inicia a aplicação com prioridade de processamento alta no Windows (<code className="text-slate-200">start /high</code>) e abre a interface local.
                </p>
                <div className="bg-slate-900 p-2.5 rounded font-mono text-xs text-slate-300 flex items-center justify-between">
                  <span>scripts\windows\run-winhood-desktop.bat</span>
                  <button
                    onClick={() => copyToClipboard('scripts\\windows\\run-winhood-desktop.bat', 'run-bat')}
                    className="text-slate-400 hover:text-white"
                  >
                    {copiedKey === 'run-bat' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              <div className="border border-slate-800 bg-slate-950 rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-bold text-white flex items-center gap-2">
                    <Layers className="w-4 h-4 text-[#31d6c4]" />
                    2. Gerador do Instalador .EXE (NSIS / Electron)
                  </div>
                  <span className="text-xs text-slate-500 font-mono">dist/</span>
                </div>
                <p className="text-xs text-slate-400">
                  Compila o executável autônomo <code className="text-slate-200">WinHood-Setup.exe</code> e a versão portátil para distribuição.
                </p>
                <div className="bg-slate-900 p-2.5 rounded font-mono text-xs text-slate-300 flex items-center justify-between">
                  <span>scripts\windows\build-windows-exe.bat</span>
                  <button
                    onClick={() => copyToClipboard('scripts\\windows\\build-windows-exe.bat', 'build-bat')}
                    className="text-slate-400 hover:text-white"
                  >
                    {copiedKey === 'build-bat' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Comparative Parity & Technical Differentiators Matrix: WinHood v4.5 vs. SonarCloud (MQR) */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-sm font-bold text-white">
            <ShieldCheck className="w-4 h-4 text-[#31d6c4]" />
            Matriz Comparativa de Capacidades Reais: WinHood Engine v4.5 vs. SonarCloud (MQR)
          </div>
          <span className="text-[11px] font-mono px-2.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
            15 Sinks Taint · AST/CFG · SBOM CycloneDX 1.5 · Hash-Chain SHA-256
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[10px]">
                <th className="py-2 pr-4">Dimensão de Engenharia</th>
                <th className="py-2 px-4">SonarCloud (MQR)</th>
                <th className="py-2 pl-4 text-[#31d6c4]">WinHood Native Engine v4.5</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              <tr>
                <td className="py-2.5 pr-4 font-medium text-white">SAST & Taint Analysis Interprocedural</td>
                <td className="py-2.5 px-4">Taint comercial em planos pagos</td>
                <td className="py-2.5 pl-4 text-emerald-300">
                  15 Sinks OWASP/CWE (SQLi, CMDi, Path, XSS, SSRF, NoSQLi, LDAPi, XPathi, XXE, Deserialization, Open Redirect, SSTI, Prototype Pollution, Logi)
                </td>
              </tr>
              <tr>
                <td className="py-2.5 pr-4 font-medium text-white">AST, CFG & Clean Code Rules</td>
                <td className="py-2.5 px-4">Regras S2871, S3923, S8786, S8233, S8543</td>
                <td className="py-2.5 pl-4 text-emerald-300">
                  Paridade nativa Babel AST + GitHub Actions IaC (S8233/S8543) + CPD Karp-Rabin
                </td>
              </tr>
              <tr>
                <td className="py-2.5 pr-4 font-medium text-white">SCA, SBOM & Licenças SPDX</td>
                <td className="py-2.5 px-4">Não gera SBOM CycloneDX/SPDX nativo</td>
                <td className="py-2.5 pl-4 text-emerald-300">
                  CycloneDX 1.5 + SPDX 2.3 assinados + correlação OSV/NVD/EPSS/CISA KEV
                </td>
              </tr>
              <tr>
                <td className="py-2.5 pr-4 font-medium text-white">Cifragem em Repouso & Rastreabilidade Forense</td>
                <td className="py-2.5 px-4">Armazenamento SaaS externo sem hash-chain local</td>
                <td className="py-2.5 pl-4 text-emerald-300">
                  Cofre local AES-256-GCM (whdb:enc:v2) + Cadeia Merkle SHA-256 + Manifesto HMAC
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

