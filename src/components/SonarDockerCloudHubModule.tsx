import React, { useState, useEffect } from 'react';
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
} from 'lucide-react';
import type { HardwareProfile } from '../engine/workerPool';

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
}

export const SonarDockerCloudHubModule: React.FC<Props> = ({ onNotify }) => {
  const [activeTab, setActiveTab] = useState<'docker' | 'cloud' | 'scanner' | 'hardware'>('docker');

  // SonarQube Docker state
  const [dockerStatus, setDockerStatus] = useState<SonarDockerStatus | null>(null);
  const [testingDocker, setTestingDocker] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // SonarScanner Generator state
  const [scannerEcosystem, setScannerEcosystem] = useState<'nodejs' | 'maven' | 'gradle' | 'dotnet' | 'cli'>('nodejs');
  const [projectKey, setProjectKey] = useState('MEU_PROJETO');
  const [hostUrl, setHostUrl] = useState('http://localhost:9000');
  const [token, setToken] = useState('squ_token_exemplo123456');

  // SonarCloud state
  const [cloudOrg, setCloudOrg] = useState('minha-organizacao');
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

  useEffect(() => {
    void checkDockerStatus();
    void loadHardwareProfile();
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
        onNotify(`SonarQube Docker conectado com sucesso! Latência: ${data.latencyMs}ms.`, 'success');
      } else {
        onNotify(
          data.errorMessage || 'SonarQube Docker não respondeu. Certifique-se de que o container está em execução.',
          'error'
        );
      }
      void checkDockerStatus();
    } catch {
      onNotify('Falha na comunicação de rede com o SonarQube.', 'error');
    } finally {
      setTestingDocker(false);
    }
  };

  const testCloudConnection = async () => {
    if (!cloudToken.trim()) {
      onNotify('Informe o token do SonarCloud para testar a conexão.', 'error');
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
        setCloudResult({ ok: true, message: 'Autenticado com sucesso na API do SonarCloud!' });
        onNotify('Conexão com SonarCloud validada com sucesso!', 'success');
      } else {
        setCloudResult({
          ok: false,
          message: data.errorMessage || 'Falha ao autenticar no SonarCloud. Verifique seu token e organização.',
        });
        onNotify('Falha ao autenticar no SonarCloud.', 'error');
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
      install: 'npm install -D sonarqube-scanner',
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
    'docker run -d --name sonarqube -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true -p 9000:9000 sonarqube:latest';

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-[#31d6c4]/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-[#31d6c4] tracking-wider uppercase">
              <Server className="w-4 h-4" />
              Sonar Hub Oficial & Motor Windows Multi-Core
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight">
              SonarQube Local (Docker) vs SonarCloud (Nuvem)
            </h1>
            <p className="text-sm text-slate-400 max-w-3xl leading-relaxed">
              Execute a análise de código do SonarQube via container oficial Docker sem necessidade de baixar zips pesados
              na máquina física, conecte ao SonarCloud na nuvem e utilize o poder multithread dos núcleos do seu processador.
            </p>
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
            Opção A: SonarQube Local (Docker)
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
            Opção B: SonarCloud (Nuvem)
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
            Gerador SonarScanner CLI
          </button>
          <button
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

      {/* TAB 1: SonarQube Local (Docker) */}
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
                  Servidor SonarQube & Motor de Análise em 1 Clique
                </h2>
                <p className="text-xs text-slate-400 max-w-2xl leading-relaxed">
                  Você não precisa abrir terminais, baixar zips pesados nem saber comandos do Docker.
                  O backend gerencia o container do SonarQube automaticamente ou ativa o motor nativo local de alta performance
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
                      : 'Iniciar SonarQube Automaticamente (1 Clique)'}
                  </button>
                ) : (
                  <button
                    onClick={handleStopDocker}
                    disabled={stoppingDocker}
                    className="inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-xs font-bold bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 border border-rose-500/30 transition-colors cursor-pointer disabled:opacity-50"
                  >
                    {stoppingDocker ? 'Pausando...' : 'Pausar Container SonarQube'}
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
                    Status do SonarQube em http://localhost:9000
                    <span className="text-xs text-slate-400 font-normal">
                      · {dockerStatus?.isReachable ? 'ONLINE (Pronto)' : 'OFFLINE (Aguardando container)'}
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {dockerStatus?.isReachable
                      ? `Conexão estabelecida com sucesso. Versão do Sonar: ${dockerStatus.version || 'Detectada'}. Latência: ${dockerStatus.latencyMs}ms.`
                      : 'O container SonarQube não está ativo no momento. Clique no botão acima para iniciar automaticamente.'}
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
              Suba o container oficial do SonarQube no seu terminal
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              A forma mais rápida e limpa de rodar o servidor local do SonarQube sem sujar o sistema operacional com
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
                . O SonarQube leva cerca de 20 a 40 segundos para inicializar os serviços internos na primeira vez.
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

      {/* TAB 2: SonarCloud (Nuvem) */}
      {activeTab === 'cloud' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center gap-2 text-base font-bold text-white">
              <Cloud className="w-5 h-5 text-[#31d6c4]" />
              Opção B: SonarCloud (100% em Nuvem - Sem Instalação Local)
            </div>
            <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
              Se você não quiser instalar nem rodar o Docker na sua máquina, utilize a versão oficial na nuvem
              (SonarCloud), ideal para integração contínua (CI/CD) direta com repositórios GitHub, GitLab e Bitbucket.
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
                  O SonarCloud ativará a análise automática a cada novo commit e pull request sem necessidade de servidor local.
                </p>
              </div>
            </div>
          </div>

          {/* Test SonarCloud Token Form */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
            <h3 className="text-sm font-bold text-white">Vincular e Validar Credenciais do SonarCloud</h3>
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
                  Token de Acesso SonarCloud
                </label>
                <input
                  id="hub-cloud-token"
                  type="password"
                  value={cloudToken}
                  onChange={(e) => setCloudToken(e.target.value)}
                  placeholder="Insira seu token gerado no SonarCloud My Account > Security"
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
                {testingCloud ? 'Validando no SonarCloud...' : 'Testar Conexão SonarCloud'}
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
                  Envie os dados do seu código local para o servidor SonarQube gerando o comando correspondente à stack do seu projeto.
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
                  type="text"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
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
    </div>
  );
};
