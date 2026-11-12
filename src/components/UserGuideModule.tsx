import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Award,
  BookOpen,
  CheckCircle2,
  Code2,
  Copy,
  Cpu,
  Download,
  FileText,
  FolderGit2,
  GitBranch,
  HelpCircle,
  Layers,
  Play,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Terminal,
  Wrench,
} from 'lucide-react';
import type { AppNavSection } from './StepByStepJourneyBar';
import { WinHoodLogo } from './WinHoodLogo';

export type GuideChapterId =
  | 'quickstart'
  | 'benchmark-weights'
  | 'ab-case-study'
  | 'sonarqube-guide'
  | 'gitar-security-guide'
  | 'glossary-faq';

interface UserGuideModuleProps {
  initialChapterId?: string;
  hasEvaluations: boolean;
  softwaresCount: number;
  onNavigate: (tab: AppNavSection) => void;
  onSeedRealWorkspace: () => Promise<void>;
  onOpenUploadModal: () => void;
  onOpenGitHubModal: () => void;
  onNotify: (msg: string, type?: 'success' | 'error') => void;
}

interface GlossaryEntry {
  term: string;
  category: 'Pontuação & Matemática' | 'Segurança & DevSecOps' | 'SonarQube & SARIF' | 'Gitar AI & CI' | 'Arquitetura & Performance';
  simpleExplanation: string;
  practicalImpactAB: string;
}

const GLOSSARY_ENTRIES: GlossaryEntry[] = [
  {
    term: 'Escala Determinística (0.00 a 5.00)',
    category: 'Pontuação & Matemática',
    simpleExplanation:
      'Todas as notas do WinHood Analyzer variam de 0.00 (crítico/inaceitável) a 5.00 (excelência técnica). "Determinística" significa que os mesmos arquivos de código e os mesmos pesos sempre produzem exatamente a mesma nota, sem sorteios ou variações aleatórias.',
    practicalImpactAB:
      'Permite comparar o Software A contra o Software B com justiça matemática auditável: notas ≥ 4.00 indicam pronto para produção; notas < 3.00 indicam reprovação técnica.',
  },
  {
    term: 'Kill Switch / Penalty Cap (Trava Matemática)',
    category: 'Pontuação & Matemática',
    simpleExplanation:
      'É um freio de segurança automático. Se um software tiver vulnerabilidades críticas (como SQL Injection ou execução remota de comandos) ou chaves secretas expostas no código, o motor limita ("trava") a nota máxima dele (ex.: teto de 2.20 / 5.00), mesmo que ele tenha boa pontuação em documentação ou interface.',
    practicalImpactAB:
      'Impede que um software perigoso vença a comparação A/B apenas porque possui tela bonita ou muitos recursos visuais.',
  },
  {
    term: 'Soma Exata de 100% nos Pesos',
    category: 'Pontuação & Matemática',
    simpleExplanation:
      'No Wizard de Benchmark, você distribui a importância percentual entre as 12 categorias (Segurança, Qualidade, Arquitetura, Desempenho, etc.). O sistema exige que a soma seja exatamente 100% antes de liberar a execução.',
    practicalImpactAB:
      'Garante transparência nos critérios de decisão da sua empresa (ex.: dar 25% de peso para Segurança em softwares financeiros).',
  },
  {
    term: 'SAST (Static Application Security Testing)',
    category: 'Segurança & DevSecOps',
    simpleExplanation:
      'Inspeção direta do código-fonte (sem precisar executar o programa em produção) para encontrar vulnerabilidades como SQL Injection, Command Injection (RCE), algoritmos criptográficos quebrados (MD5/ECB) e desserialização insegura.',
    practicalImpactAB:
      'Descobre falhas graves no código do Software A ou B antes mesmo de instalá-lo na rede corporativa.',
  },
  {
    term: 'SCA (Software Composition Analysis)',
    category: 'Segurança & DevSecOps',
    simpleExplanation:
      'Análise das bibliotecas e pacotes de terceiros (como package.json, requirements.txt, pom.xml) em busca de versões desatualizadas ou com falhas de segurança públicas conhecidas (CVEs).',
    practicalImpactAB:
      'Revela qual dos dois softwares carrega "dívida oculta" de bibliotecas vulneráveis.',
  },
  {
    term: 'Detecção e Mascaramento de Segredos (Secrets)',
    category: 'Segurança & DevSecOps',
    simpleExplanation:
      'Localiza senhas, tokens de API, chaves privadas e chaves mestras esquecidas dentro do código-fonte. Ao exibir o trecho na tela ou no relatório, o sistema mascara automaticamente o valor real (ex.: VC_***) para nunca vazar a credencial.',
    practicalImpactAB:
      'Qualquer segredo hardcoded encontrado aciona imediatamente o Kill Switch de Segurança.',
  },
  {
    term: 'Quality Gate (Portão de Qualidade SonarQube)',
    category: 'SonarQube & SARIF',
    simpleExplanation:
      'Conjunto de regras de aprovação do SonarQube (ex.: 0 novas vulnerabilidades, cobertura de testes ≥ 80%, duplicação de código ≤ 5%). Retorna status OK (Aprovado), WARN (Alerta) ou ERROR (Reprovado).',
    practicalImpactAB:
      'Na comparação A/B padronizada com SonarQube, ambos os softwares passam exatamente pelo mesmo Quality Gate na mesma instância.',
  },
  {
    term: 'SARIF v2.1.0 (Relatórios Externos Importados)',
    category: 'SonarQube & SARIF',
    simpleExplanation:
      'Static Analysis Results Interchange Format — padrão internacional em JSON usado por ferramentas como Semgrep/OpenGrep, Gitleaks e Trivy para exportar seus achados para o SonarQube e para o WinHood Analyzer.',
    practicalImpactAB:
      'O sistema classifica separadamente o que é nativo do SonarQube e o que foi importado via SARIF, evitando contar o mesmo problema duas vezes.',
  },
  {
    term: 'Compute Engine (Tarefas CE do SonarQube)',
    category: 'SonarQube & SARIF',
    simpleExplanation:
      'Fila interna de processamento do servidor SonarQube (/api/ce/task) que recebe o relatório enviado pelo SonarScanner e calcula as métricas e o Quality Gate.',
    practicalImpactAB:
      'O WinHood Analyzer monitora a tarefa CE até o status SUCCESS (ou captura falhas CANCELED/FAILED com diagnóstico detalhado).',
  },
  {
    term: 'Gitar AI — Aprovação Humana em Branch Isolada',
    category: 'Gitar AI & CI',
    simpleExplanation:
      'Integração na categoria AI CODE REVIEW & REMEDIATION que analisa Pull Requests e falhas de CI, propondo correções de código (diff Antes/Depois) exclusivamente em uma branch separada (gitar/remediation-isolated/*).',
    practicalImpactAB:
      'Jamais altera os arquivos originais dos Softwares A e B automaticamente; exige que um engenheiro humano revise e clique em Aprovar ou Rejeitar.',
  },
  {
    term: 'Dependência Circular & Violação de Camada',
    category: 'Arquitetura & Performance',
    simpleExplanation:
      'Dependência circular ocorre quando dois módulos importam um ao outro em ciclo fechado. Violação de camada ocorre quando uma camada superior (ex.: UI) acessa diretamente uma camada restrita (ex.: banco SQL) pulando a camada de serviço.',
    practicalImpactAB:
      'Penaliza a nota de Arquitetura & Modularidade do software infrator, indicando alto custo futuro de manutenção.',
  },
  {
    term: 'Cache Imutável SHA-256 (8 Fatores)',
    category: 'Arquitetura & Performance',
    simpleExplanation:
      'Mecanismo de otimização de recursos que armazena o resultado de uma análise associando-o ao hash SHA-256 do commit, versão do scanner, perfil de qualidade e regras. Se nada mudou, reutiliza o resultado em milissegundos.',
    practicalImpactAB:
      'Economiza CPU, memória e tempo sem jamais entregar resultados desatualizados quando o código muda.',
  },
];

const FAQ_ENTRIES = [
  {
    q: '1. Por que o Dashboard começa vazio quando clico em "Simular Estado Inicial Vazio"?',
    a: 'Por respeito à política de Veracidade Estrita da plataforma: o WinHood Analyzer nunca inventa notas ou gráficos falsos quando não há uma avaliação executada. Para ver dados reais imediatamente, basta clicar em "Carregar Exemplo Real A/B (VaultCore vs KeeSafe)" ou cadastrar seus próprios softwares no Passo 1.',
  },
  {
    q: '2. Como comparo dois projetos meus que estão no meu computador ou no GitHub?',
    a: 'Use os botões "Upload" (para enviar uma pasta ou arquivos do seu computador) ou "GitHub" (para buscar qualquer repositório público do GitHub em tempo real) localizados no canto superior direito da barra de topo. Associe ambos ao mesmo Projeto e depois execute o Passo 2 (Wizard de Benchmark).',
  },
  {
    q: '3. Por que o SonarQube Local aparece como "NOT_INSTALLED" neste ambiente em nuvem?',
    a: 'Porque o container de preview roda sob kernel Linux gVisor sem Java 21 (JDK 21) e sem permissão de kernel para vm.max_map_count=524288 (exigido pelo Elasticsearch do SonarQube Server). Em vez de fingir que o servidor local está rodando, o sistema informa honestamente o status real, disponibiliza os scripts oficiais de instalação para sua máquina host (Windows/Linux) e permite executar a Comparação Padronizada A/B e os 27 Testes Reais de Contrato da Web API.',
  },
  {
    q: '4. O Gitar AI pode alterar o código-fonte original dos softwares que estou avaliando?',
    a: 'Não! Por design de segurança, o Gitar AI opera em modo somente-leitura sobre os repositórios avaliados. Qualquer sugestão de correção (patch) é gerada em uma branch isolada separada e fica retida no estado PENDING_HUMAN_APPROVAL até que você revise o diff Antes/Depois e aprove ou rejeite manualmente.',
  },
  {
    q: '5. Como sei se um número na tela veio do SonarQube ou do próprio WinHood Benchmark Analyzer?',
    a: 'Na aba "Ferramentas e Integrações -> Comparação Padronizada A/B", cada indicador possui uma etiqueta explícita de origem: SONARQUBE_NATIVE (métrica oficial retornada pela API do SonarQube), BENCHMARK_CALCULATED (nota composta calculada pelo motor matemático do WinHood) ou EXTERNAL_TEST_REPORT_IMPORTED (achado importado de relatório SARIF externo).',
  },
];

export const COMPLETE_USER_GUIDE_MARKDOWN = `# Guia Completo de Utilização — WinHood Software Benchmark & Quality Analyzer

## 1. Visão Geral do Sistema
O **WinHood Software Benchmark & Quality Analyzer** é uma plataforma de engenharia de qualidade, segurança (AppSec/DevSecOps) e arquitetura projetada para comparar dois ou mais softwares (**Software A vs. Software B**) de forma 100% determinística, auditável por hashes criptográficos **SHA-256** e livre de métricas simuladas.

---

## 2. A Jornada de Análise em 6 Passos Numerados

### Passo 1: Cadastrar ou Importar os Softwares A e B (\`Projetos & Softwares\`)
- **Opção A — Upload Local**: Clique no botão **Upload** no topo da tela para enviar arquivos de código-fonte (\`.ts\`, \`.js\`, \`.py\`, \`.sql\`, \`.json\`, \`.md\`, etc.) diretamente do seu computador.
- **Opção B — Importação do GitHub**: Clique no botão **GitHub** no topo para pesquisar repositórios reais no GitHub e importar sua árvore de código automaticamente.
- **Opção C — Demonstração Real com 1 Clique**: Clique em **Carregar Exemplo Real A/B (VaultCore vs KeeSafe)** para carregar dois cofres de senhas completos e contrastantes prontos para inspeção.

### Passo 2: Configurar Pesos Matemáticos e Executar o Benchmark (\`Wizard de Benchmark\`)
1. Escolha o **Projeto** e selecione os softwares que deseja confrontar.
2. Configure os pesos das **12 Categorias de Avaliação**:
   - *Segurança & Criptografia*, *Qualidade de Código*, *Arquitetura*, *Funcionalidades*, *Desempenho*, *Banco de Dados*, *Confiabilidade*, *Compatibilidade*, *Usabilidade*, *Instalação (T0/T1/T2)*, *Privacidade* e *Documentação*.
   - **Regra Matemática Obrigatória**: A soma dos pesos deve totalizar **exatamente 100%**.
3. Verifique as **Condições de Equivalência de Ambiente** (CPU, Memória RAM, Sistema Operacional e concorrência) e clique em **Executar Benchmark Determinístico Real**.

### Passo 3: Qualidade Contínua com SonarQube, SARIF e Gitar AI (\`Ferramentas e Integrações\`)
- **4 Cartões Independentes**:
  1. **SonarQube Community Build (Servidor Local)**: Gerencia instalação oficial v26.11.0.134175, validação SHA-256 e ciclo de vida sob demanda.
  2. **SonarQube Servidor Remoto**: Conecta a qualquer instância corporativa via token Bearer criptografado em repouso (\`AES-256-GCM\`).
  3. **SonarQube Cloud (SaaS)**: Integração com \`sonarcloud.io\` informando \`organization\` e \`projectKey\`.
  4. **Gitar AI (\`AI CODE REVIEW & REMEDIATION\`)**: Importa revisões de Pull Requests e diagnósticos de falha de CI com sugestões de correção em branch isolada e aprovação humana obrigatória.
- **Comparação Padronizada A/B com SonarQube**: Avalia Software A e Software B sequencialmente na mesma instância, com mesmo scanner (\`8.4.0.16527\`), mesmo perfil de qualidade (\`Sonar way\`) e mesmo Quality Gate.
- **Suíte de 27 Testes Reais de Integração**: Executa 15 etapas principais do pipeline ponta a ponta + 12 testes negativos de injeção de falhas (token inválido, HTTP 403, HTTP 404, tarefa CE cancelada, JSON corrompido, timeout, etc.).

### Passo 4: Auditar Segurança, Qualidade e Arquitetura (\`Suíte de Segurança\`, \`Qualidade & DevSecOps\`, \`Arquitetura, QA & Perf\`)
- **Suíte de Segurança & Resiliência**: 15 módulos especializados, 21 adaptadores técnicos, mapeamento de **Superfície de Ataque** e **Cadeias de Exploração (Attack Paths)** com 6 estados de validação (\`CONFIRMADA\`, \`PROVAVEL\`, \`FALSO_POSITIVO\`, \`NAO_REPRODUZIVEL\`, \`INCONCLUSIVA\`, \`NAO_TESTADA\`).
- **Qualidade & DevSecOps**: Lista detalhada de achados SAST, Segredos (mascarados automaticamente), SCA e SQL com linha exata e recomendação de mitigação.
- **Arquitetura, QA & Performance**: Grafo de acoplamento, detecção de dependências circulares, violações de camada, complexidade ciclomática e latência P95.

### Passo 5: Verificar Autenticidade e Provas Criptográficas (\`Veracidade & Adaptadores\`)
- Audite o status real de cada ferramenta no sistema operacional e confira a **Cadeia de Evidências SHA-256** imutável gerada em cada etapa da execução.

### Passo 6: Exportar Relatórios e Tomar Decisão Executiva (\`Relatórios & Auditoria\`)
- Baixe o laudo técnico completo em **JSON**, **Markdown (.md)** ou **HTML/PDF pronto para impressão**, contendo o vencedor técnico validado e todas as justificativas matemáticas.

---

## 3. Estudo de Caso Prático A/B: VaultCore Internal vs. KeeSafe Open

| Dimensão Avaliada | Software A: VaultCore Internal v2.4.0 | Software B: KeeSafe Open v2.56.0 | Impacto na Decisão |
| :--- | :--- | :--- | :--- |
| **Segurança SAST & Criptografia** | Usa \`MD5\`, \`AES-128-ECB\`, \`Math.random()\` e concatenação SQL direta (\`SQL Injection\`) + \`execSync\` (\`RCE\`) | Usa \`AES-256-GCM\`, \`PBKDF2-SHA512\` (600.000 iterações) e queries parametrizadas seguras | **KeeSafe Open** protege o cofre; **VaultCore** permite invasão trivial |
| **Segredos Expostos (Secrets)** | Possui chave mestra hardcoded no código (\`VC_***\`) | Zero segredos expostos no código-fonte | Aciona **Kill Switch** no VaultCore |
| **Arquitetura & Modularidade** | Possui dependência circular e violação de camada (UI acessando SQL direto) | Camadas desacopladas, zero ciclos e trilha de auditoria imutável | **KeeSafe Open** tem manutenção limpa e previsível |
| **Quality Gate SonarQube** | **ERROR (Reprovado)** — Security Rating E | **OK (Aprovado)** — Ratings A em Confiabilidade, Segurança e Manutenibilidade | **KeeSafe Open** passa no Quality Gate padronizado |
| **Nota Composta Final (0–5)** | **≤ 2.20 / 5.00** (Bloqueado por Travas Matemáticas / Kill Switches) | **> 4.50 / 5.00** (**Vencedor Técnico Validado**) | Recomendação executiva inequívoca para **KeeSafe Open** |
`;

export const UserGuideModule: React.FC<UserGuideModuleProps> = ({
  initialChapterId = 'quickstart',
  hasEvaluations,
  softwaresCount,
  onNavigate,
  onSeedRealWorkspace,
  onOpenUploadModal,
  onOpenGitHubModal,
  onNotify,
}) => {
  const [activeChapter, setActiveChapter] = useState<GuideChapterId>(
    (initialChapterId as GuideChapterId) || 'quickstart'
  );
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedGlossaryCategory, setSelectedGlossaryCategory] = useState<string>('TODOS');

  // Sincronizar quando initialChapterId mudar externamente
  React.useEffect(() => {
    if (
      initialChapterId &&
      [
        'quickstart',
        'benchmark-weights',
        'ab-case-study',
        'sonarqube-guide',
        'gitar-security-guide',
        'glossary-faq',
      ].includes(initialChapterId)
    ) {
      setActiveChapter(initialChapterId as GuideChapterId);
    }
  }, [initialChapterId]);

  const chapters: Array<{
    id: GuideChapterId;
    levelBadge: 'BÁSICO' | 'INTERMEDIÁRIO' | 'EXEMPLO PRÁTICO' | 'AVANÇADO' | 'REFERÊNCIA';
    title: string;
    subtitle: string;
    icon: React.ComponentType<{ className?: string }>;
  }> = [
    {
      id: 'quickstart',
      levelBadge: 'BÁSICO',
      title: '1. Início Rápido & Jornada em 6 Passos',
      subtitle: 'Como operar a plataforma do zero em menos de 5 minutos',
      icon: Play,
    },
    {
      id: 'benchmark-weights',
      levelBadge: 'INTERMEDIÁRIO',
      title: '2. Pesos Matemáticos (100%) & Kill Switches',
      subtitle: 'Como funcionam as notas de 0 a 5 e as travas eliminatórias',
      icon: Sliders,
    },
    {
      id: 'ab-case-study',
      levelBadge: 'EXEMPLO PRÁTICO',
      title: '3. Estudo de Caso A/B: VaultCore vs. KeeSafe',
      subtitle: 'Exemplo comentado passo a passo de uma comparação real',
      icon: Award,
    },
    {
      id: 'sonarqube-guide',
      levelBadge: 'AVANÇADO',
      title: '4. SonarQube, SonarScanner, Cloud & SARIF',
      subtitle: 'Instalação oficial, Web API, Quality Gate A/B e 27 testes reais',
      icon: Wrench,
    },
    {
      id: 'gitar-security-guide',
      levelBadge: 'AVANÇADO',
      title: '5. Gitar AI & Suíte de Segurança (21 Adaptadores)',
      subtitle: 'Revisão assistida em branch isolada e superfície de ataque',
      icon: ShieldAlert,
    },
    {
      id: 'glossary-faq',
      levelBadge: 'REFERÊNCIA',
      title: '6. Glossário Técnico & Perguntas Frequentes',
      subtitle: 'Significado claro de todas as siglas, métricas e estados',
      icon: HelpCircle,
    },
  ];

  const filteredGlossary = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return GLOSSARY_ENTRIES.filter((entry) => {
      const matchesCat =
        selectedGlossaryCategory === 'TODOS' || entry.category === selectedGlossaryCategory;
      const matchesQuery =
        !q ||
        entry.term.toLowerCase().includes(q) ||
        entry.simpleExplanation.toLowerCase().includes(q) ||
        entry.practicalImpactAB.toLowerCase().includes(q);
      return matchesCat && matchesQuery;
    });
  }, [searchQuery, selectedGlossaryCategory]);

  const filteredFaq = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return FAQ_ENTRIES;
    return FAQ_ENTRIES.filter(
      (item) => item.q.toLowerCase().includes(q) || item.a.toLowerCase().includes(q)
    );
  }, [searchQuery]);

  const handleCopyText = (text: string, label: string) => {
    void navigator.clipboard.writeText(text);
    onNotify(`${label} copiado para a área de transferência!`, 'success');
  };

  const handleDownloadGuideMarkdown = () => {
    const blob = new Blob([COMPLETE_USER_GUIDE_MARKDOWN], {
      type: 'text/markdown;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'USER_GUIDE_WINHOOD_ANALYZER.md';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    onNotify('Guia Completo de Utilização (USER_GUIDE.md) baixado com sucesso!', 'success');
  };

  return (
    <div className="space-y-8">
      {/* Top Header Banner */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-5">
          <div className="flex items-start gap-4">
            <WinHoodLogo size={48} className="shrink-0" />
            <div className="space-y-1.5">
              <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md bg-[#31d6c4]/15 text-[#0e9f8e] dark:text-[#31d6c4] font-mono text-xs font-bold border border-[#31d6c4]/30">
                <BookOpen className="w-3.5 h-3.5" />
                <span>MANUAL INTERATIVO OFICIAL — DO BÁSICO AO AVANÇADO</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
                Guia de Utilização &amp; Entendimento do WinHood Analyzer
              </h1>
              <p className="text-sm text-slate-600 dark:text-slate-400 max-w-3xl leading-relaxed">
                Aprenda passo a passo como cadastrar softwares, configurar pesos matemáticos, interpretar travas de segurança (Kill Switches), operar o SonarQube / Gitar AI e emitir laudos técnicos comparativos A/B.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={handleDownloadGuideMarkdown}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#090d13] text-slate-800 dark:text-slate-200 hover:border-[#31d6c4] transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-[#31d6c4]" />
              <span>Baixar Manual Completo (.MD)</span>
            </button>

            {!hasEvaluations && (
              <button
                type="button"
                onClick={onSeedRealWorkspace}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Carregar Exemplo Real A/B Agora</span>
              </button>
            )}
          </div>
        </div>

        {/* Showcase Oficial da Identidade Visual "01. WinHood Pulse" */}
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#080b10] p-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1">
            <div className="text-xs font-mono font-bold text-[#31d6c4]">
              01. WINHOOD PULSE — IDENTIDADE VISUAL OFICIAL
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400 max-w-xl">
              Duplo Chevron &ldquo;W&rdquo; em Turquesa SLA (<code className="font-mono">#31d6c4</code>) sobre arco de suporte concêntrico segmentado no gradiente Wini IA (<code className="font-mono">#a855f7 → #6366f1 → #3b82f6</code>). Projetado para nitidez vetorial em <code className="font-mono">.brand-mark 34x34px</code>, headers <code className="font-mono">48px</code> e showcase <code className="font-mono">160px</code>.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-4 shrink-0">
            <div className="flex items-center gap-2.5 rounded-lg border border-slate-800 bg-[#0d1117] px-3.5 py-2">
              <WinHoodLogo size={48} variant="dark" />
              <div className="text-[11px] font-mono text-slate-300">
                <div className="font-bold text-white">Dark Mode</div>
                <div>#0d1117 · 160/48px</div>
              </div>
            </div>
            <div className="flex items-center gap-2.5 rounded-lg border border-slate-200 bg-white px-3.5 py-2">
              <WinHoodLogo size={48} variant="light" />
              <div className="text-[11px] font-mono text-slate-700">
                <div className="font-bold text-slate-900">Light Mode</div>
                <div>#ffffff · 160/48px</div>
              </div>
            </div>
            <div className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2">
              <WinHoodLogo size={34} className="brand-mark" />
              <div className="text-[11px] font-mono text-slate-300">
                <div className="font-bold text-[#31d6c4]">.brand-mark</div>
                <div>34x34px</div>
              </div>
            </div>
          </div>
        </div>

        {/* Search & Quick Status Bar */}
        <div className="pt-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
          <div className="relative flex-1 max-w-xl">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                if (e.target.value.trim().length > 1 && activeChapter !== 'glossary-faq') {
                  setActiveChapter('glossary-faq');
                }
              }}
              placeholder="Pesquisar termo técnico, métrica (ex.: Kill Switch, SAST, SARIF, Quality Gate, Gitar)..."
              className="w-full pl-10 pr-4 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#31d6c4]"
            />
          </div>

          <div className="flex items-center gap-3 text-xs font-mono">
            <span className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#090d13] text-slate-600 dark:text-slate-300">
              Softwares no Workspace: <strong className="text-[#0e9f8e] dark:text-[#31d6c4]">{softwaresCount}</strong>
            </span>
            <span className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#090d13] text-slate-600 dark:text-slate-300">
              Status A/B:{' '}
              <strong className={hasEvaluations ? 'text-emerald-500' : 'text-amber-500'}>
                {hasEvaluations ? 'AVALIAÇÃO CONCLUÍDA' : 'AGUARDANDO EXECUÇÃO'}
              </strong>
            </span>
          </div>
        </div>
      </div>

      {/* Chapter Navigation Grid (6 Chapters from Basic to Advanced) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {chapters.map((chap) => {
          const Icon = chap.icon;
          const isSelected = activeChapter === chap.id;
          return (
            <button
              key={chap.id}
              type="button"
              onClick={() => setActiveChapter(chap.id)}
              className={`text-left p-4 rounded-xl border transition-all cursor-pointer flex items-start gap-3.5 ${
                isSelected
                  ? 'bg-white dark:bg-[#111823] border-[#31d6c4] ring-1 ring-[#31d6c4]/30'
                  : 'bg-white/70 dark:bg-[#0c1017] border-slate-200 dark:border-slate-800/80 hover:border-slate-300 dark:hover:border-slate-700'
              }`}
            >
              <div
                className={`p-2.5 rounded-lg shrink-0 ${
                  isSelected
                    ? 'bg-[#31d6c4] text-slate-950'
                    : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300'
                }`}
              >
                <Icon className="w-4 h-4" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-[#0e9f8e] dark:text-[#31d6c4]">
                    {chap.levelBadge}
                  </span>
                  {isSelected && (
                    <span className="text-[10px] font-mono font-semibold text-[#0e9f8e] dark:text-[#31d6c4]">
                      Capítulo Ativo
                    </span>
                  )}
                </div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-1.5">
                  {chap.title}
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 leading-snug">
                  {chap.subtitle}
                </p>
              </div>
            </button>
          );
        })}
      </div>

      {/* CHAPTER 1: QUICKSTART & 6-STEP JOURNEY */}
      {activeChapter === 'quickstart' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-6 space-y-6">
            <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
              <span className="text-xs font-mono font-bold text-[#0e9f8e] dark:text-[#31d6c4]">
                CAPÍTULO 1 — NÍVEL BÁSICO
              </span>
              <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100 mt-1">
                Como funciona o WinHood Analyzer e como realizar sua primeira comparação A/B
              </h2>
              <p className="text-sm text-slate-600 dark:text-slate-300 mt-1 max-w-4xl leading-relaxed">
                O objetivo da plataforma é responder com provas técnicas à pergunta:{' '}
                <strong>
                  "Entre o Software A e o Software B, qual é mais seguro, mais bem construído e mais confiável para utilizarmos?"
                </strong>
              </p>
            </div>

            {/* 3 Ways to Load Softwares */}
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3">
                3 Formas de Começar (Como inserir softwares para análise)
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#090d13] p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-2 text-xs font-bold text-[#0e9f8e] dark:text-[#31d6c4]">
                      <Play className="w-4 h-4" />
                      <span>OPÇÃO 1 (Mais Rápida — 1 Clique)</span>
                    </div>
                    <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-2">
                      Carregar Par Real de Demonstração A/B
                    </h4>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mt-1.5 leading-relaxed">
                      Ingere automaticamente dois softwares reais de cofre de senhas (
                      <strong>VaultCore Internal v2.4.0</strong> vs.{' '}
                      <strong>KeeSafe Open v2.56.0</strong>), executa os motores SAST/SCA/SQL/Arquitetura e popula todas as telas.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={onSeedRealWorkspace}
                    className="mt-4 w-full py-2 px-3 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                  >
                    Carregar e Analisar Exemplo Real Agora
                  </button>
                </div>

                <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#090d13] p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-2 text-xs font-bold text-indigo-500 dark:text-indigo-400">
                      <FolderGit2 className="w-4 h-4" />
                      <span>OPÇÃO 2 (Seus Arquivos Locais)</span>
                    </div>
                    <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-2">
                      Fazer Upload de Projeto do Computador
                    </h4>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mt-1.5 leading-relaxed">
                      Envie uma pasta de projeto ou múltiplos arquivos de código-fonte (`.ts`, `.tsx`, `.js`, `.py`, `.sql`, `.json`, `.md`). O sistema calcula o hash SHA-256 de cada arquivo e monta o inventário técnico real.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={onOpenUploadModal}
                    className="mt-4 w-full py-2 px-3 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] text-slate-800 dark:text-slate-200 hover:border-[#31d6c4] transition-colors cursor-pointer"
                  >
                    Abrir Modal de Upload de Código
                  </button>
                </div>

                <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#090d13] p-4 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center gap-2 text-xs font-bold text-emerald-600 dark:text-emerald-400">
                      <GitBranch className="w-4 h-4" />
                      <span>OPÇÃO 3 (Repositórios Online)</span>
                    </div>
                    <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-2">
                      Pesquisar e Importar do GitHub
                    </h4>
                    <p className="text-xs text-slate-600 dark:text-slate-400 mt-1.5 leading-relaxed">
                      Busque qualquer repositório público no GitHub por palavra-chave ou `owner/repo`. O backend baixa a árvore de código real via API oficial do GitHub para avaliação comparativa.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={onOpenGitHubModal}
                    className="mt-4 w-full py-2 px-3 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] text-slate-800 dark:text-slate-200 hover:border-indigo-400 transition-colors cursor-pointer"
                  >
                    Pesquisar Repositório no GitHub
                  </button>
                </div>
              </div>
            </div>

            {/* Detailed Walkthrough of the 6 Numbered Steps */}
            <div className="space-y-3 pt-2">
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Explicação Detalhada dos 6 Passos da Barra de Jornada (Topo da Tela)
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  {
                    num: 'PASSO 1',
                    title: 'Projetos & Softwares (Cadastro e Inventário SHA-256)',
                    desc: 'Agrupe os softwares concorrentes dentro de um mesmo Projeto. Para cada software cadastrado, você pode clicar em "Inspecionar Inventário Técnico" para ver exatamente quantos arquivos, linhas de código (LOC) e linguagens foram detectados.',
                    nav: 'projects' as AppNavSection,
                    btnLabel: 'Ir para Passo 1: Projetos & Softwares',
                  },
                  {
                    num: 'PASSO 2',
                    title: 'Wizard de Benchmark (Pesos Matemáticos & Execução)',
                    desc: 'Escolha o perfil de pesos (soma obrigatória de 100%), selecione os Softwares A e B e dispare a execução. O motor analisará cada arquivo real e calculará as notas de 0.00 a 5.00.',
                    nav: 'wizard' as AppNavSection,
                    btnLabel: 'Ir para Passo 2: Wizard de Benchmark',
                  },
                  {
                    num: 'PASSO 3',
                    title: 'Ferramentas e Integrações (SonarQube, SARIF & Gitar AI)',
                    desc: 'Execute a Comparação Padronizada A/B com SonarQube sob o mesmo Quality Gate, importe relatórios externos SARIF v2.1.0, valide patches do Gitar AI em branch isolada e rode a Suíte de 27 Testes de Integração.',
                    nav: 'tools_integrations' as AppNavSection,
                    btnLabel: 'Ir para Passo 3: SonarQube & Gitar AI',
                  },
                  {
                    num: 'PASSO 4',
                    title: 'Inspeção Profunda: Segurança, DevSecOps & Arquitetura',
                    desc: 'Navegue pelas abas "Suíte de Segurança & Resiliência", "Qualidade & DevSecOps" e "Arquitetura, QA & Perf" para ver caminhos de ataque (Attack Paths), linhas exatas de código vulnerável e dependências circulares.',
                    nav: 'security_suite' as AppNavSection,
                    btnLabel: 'Ir para Passo 4: Suíte de Segurança',
                  },
                  {
                    num: 'PASSO 5',
                    title: 'Veracidade & Adaptadores (Prova contra Dados Falsos)',
                    desc: 'Verifique a classificação SUCCESS_VALIDATED, o estado real dos 21 adaptadores de ferramentas no sistema operacional e a trilha de hashes SHA-256 de todas as evidências coletadas.',
                    nav: 'veracity' as AppNavSection,
                    btnLabel: 'Ir para Passo 5: Veracidade & Adaptadores',
                  },
                  {
                    num: 'PASSO 6',
                    title: 'Relatórios & Auditoria (Exportação de Laudos Oficiais)',
                    desc: 'Exporte o laudo comparativo completo em formato JSON (para automação), Markdown (para repositórios/wikis) ou HTML/PDF (para diretoria e auditoria formal).',
                    nav: 'reports' as AppNavSection,
                    btnLabel: 'Ir para Passo 6: Relatórios & Exportação',
                  },
                ].map((item) => (
                  <div
                    key={item.num}
                    className="rounded-lg border border-slate-200 dark:border-slate-800 p-4 bg-white dark:bg-[#0b0f17] flex flex-col justify-between"
                  >
                    <div>
                      <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-[#31d6c4]/15 text-[#0e9f8e] dark:text-[#31d6c4]">
                        {item.num}
                      </span>
                      <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-2">
                        {item.title}
                      </h4>
                      <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 leading-relaxed">
                        {item.desc}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() => onNavigate(item.nav)}
                      className="mt-3 inline-flex items-center gap-1.5 text-xs font-semibold text-[#0e9f8e] dark:text-[#31d6c4] hover:underline cursor-pointer"
                    >
                      <span>{item.btnLabel}</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* CHAPTER 2: BENCHMARK WEIGHTS & KILL SWITCHES */}
      {activeChapter === 'benchmark-weights' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-6 space-y-6">
            <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
              <span className="text-xs font-mono font-bold text-[#0e9f8e] dark:text-[#31d6c4]">
                CAPÍTULO 2 — NÍVEL INTERMEDIÁRIO
              </span>
              <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100 mt-1">
                Como funcionam os Pesos Matemáticos (100%), Notas de 0 a 5 e Kill Switches
              </h2>
              <p className="text-sm text-slate-600 dark:text-slate-300 mt-1 max-w-4xl leading-relaxed">
                O WinHood Analyzer utiliza um motor matemático determinístico: nenhuma nota é subjetiva. Entenda abaixo como as 12 categorias são combinadas e por que as Travas Matemáticas protegem sua decisão.
              </p>
            </div>

            {/* Score Scale Table */}
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3">
                Tabela de Interpretação das Notas (Escala 0.00 a 5.00)
              </h3>
              <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-100 dark:bg-[#090d13] border-b border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 font-mono">
                      <th className="py-2.5 px-4">Faixa de Nota</th>
                      <th className="py-2.5 px-4">Classificação</th>
                      <th className="py-2.5 px-4">Significado Prático para Decisão Executiva</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                    <tr>
                      <td className="py-3 px-4 font-mono font-bold text-emerald-600 dark:text-[#31d6c4]">
                        4.50 — 5.00
                      </td>
                      <td className="py-3 px-4 font-bold">EXCELENTE (Produção Crítica)</td>
                      <td className="py-3 px-4 text-slate-600 dark:text-slate-300">
                        Zero vulnerabilidades críticas, criptografia forte validada, arquitetura limpa sem ciclos e alta cobertura de testes. Recomendado para adoção imediata.
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 px-4 font-mono font-bold text-emerald-500">
                        3.80 — 4.49
                      </td>
                      <td className="py-3 px-4 font-bold">BOM / APROVADO COM RESSALVAS LEVES</td>
                      <td className="py-3 px-4 text-slate-600 dark:text-slate-300">
                        Seguro para uso, mas possui dívida técnica moderada ou pontos de refatoração de código que devem entrar no backlog.
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 px-4 font-mono font-bold text-amber-500">
                        2.90 — 3.79
                      </td>
                      <td className="py-3 px-4 font-bold">ATENÇÃO / RISCO MODERADO</td>
                      <td className="py-3 px-4 text-slate-600 dark:text-slate-300">
                        Apresenta falhas arquiteturais, baixa cobertura de testes ou alertas de segurança médios. Exige correção antes de ir para produção.
                      </td>
                    </tr>
                    <tr>
                      <td className="py-3 px-4 font-mono font-bold text-rose-500">
                        0.00 — 2.89
                      </td>
                      <td className="py-3 px-4 font-bold">REPROVADO / BLOQUEADO POR KILL SWITCH</td>
                      <td className="py-3 px-4 text-slate-600 dark:text-slate-300">
                        Acionou uma ou mais Travas Matemáticas Eliminatórias (ex.: SQL Injection, RCE, chave secreta vazada no código ou ausência de criptografia em repouso).
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Kill Switches Explanation */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-4 space-y-2.5">
                <div className="flex items-center gap-2 text-rose-600 dark:text-rose-400 font-bold text-sm">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>O que são as Travas Matemáticas (Kill Switches)?</span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                  Em uma média ponderada comum, um software com <strong>SQL Injection crítico</strong> poderia tirar nota `0.0` em Segurança, mas tirar `5.0` em Usabilidade, Documentação e Compatibilidade, terminando com uma média enganosa de `3.8 / 5.0`.
                </p>
                <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                  Para evitar essa distorção, o WinHood aplica <strong>Penalty Caps (Kill Switches)</strong>:
                </p>
                <ul className="text-xs text-slate-700 dark:text-slate-200 space-y-1.5 font-mono">
                  <li>• Vulnerabilidade Crítica Confirmada → Trava Segurança ≤ 1.50 e Nota Global ≤ 2.20</li>
                  <li>• Segredo / Chave Mestra Hardcoded → Trava Segurança ≤ 1.20 e Nota Global ≤ 2.00</li>
                  <li>• Sem Criptografia em Repouso (Cofre) → Trava Privacidade/Segurança ≤ 2.00</li>
                  <li>• Ambiente Não Equivalente → Bloqueia validação comparativa de Performance</li>
                </ul>
              </div>

              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#090d13] p-4 space-y-3 flex flex-col justify-between">
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-[#0e9f8e] dark:text-[#31d6c4] font-bold text-sm">
                    <Sliders className="w-4 h-4 shrink-0" />
                    <span>Pesos Padrão das 12 Categorias (Soma = 100%)</span>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400">
                    Você pode personalizar esses pesos no <strong>Wizard de Benchmark</strong> conforme a prioridade do seu projeto:
                  </p>
                  <div className="grid grid-cols-2 gap-1.5 text-xs font-mono">
                    <div className="px-2.5 py-1 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                      Segurança: <strong>18%</strong>
                    </div>
                    <div className="px-2.5 py-1 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                      Qualidade Código: <strong>14%</strong>
                    </div>
                    <div className="px-2.5 py-1 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                      Funcionalidades: <strong>12%</strong>
                    </div>
                    <div className="px-2.5 py-1 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                      Arquitetura: <strong>10%</strong>
                    </div>
                    <div className="px-2.5 py-1 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                      Desempenho: <strong>10%</strong>
                    </div>
                    <div className="px-2.5 py-1 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                      Confiabilidade: <strong>8%</strong>
                    </div>
                    <div className="px-2.5 py-1 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                      Banco de Dados: <strong>8%</strong>
                    </div>
                    <div className="px-2.5 py-1 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                      Privacidade + 4 outras: <strong>20%</strong>
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => onNavigate('wizard')}
                  className="w-full py-2 px-3 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                >
                  Abrir Wizard de Pesos e Benchmark Agora
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* CHAPTER 3: PRACTICAL A/B CASE STUDY */}
      {activeChapter === 'ab-case-study' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-6 space-y-6">
            <div className="border-b border-slate-200 dark:border-slate-800 pb-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div>
                <span className="text-xs font-mono font-bold text-[#0e9f8e] dark:text-[#31d6c4]">
                  CAPÍTULO 3 — EXEMPLO PRÁTICO COMENTADO A/B
                </span>
                <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100 mt-1">
                  Estudo de Caso Real: VaultCore Internal v2.4.0 vs. KeeSafe Open v2.56.0
                </h2>
                <p className="text-sm text-slate-600 dark:text-slate-300 mt-1 max-w-4xl leading-relaxed">
                  Veja na prática como o WinHood Analyzer examina o código-fonte real de dois gerenciadores de senhas concorrentes e fundamenta a decisão técnica.
                </p>
              </div>
              <button
                type="button"
                onClick={async () => {
                  await onSeedRealWorkspace();
                  onNavigate('dashboard');
                }}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors shrink-0 cursor-pointer"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Executar Este Caso no Dashboard</span>
              </button>
            </div>

            {/* Side-by-Side Practical Breakdown */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Software A: VaultCore */}
              <div className="rounded-xl border border-rose-500/40 bg-rose-500/5 p-5 space-y-4">
                <div className="flex items-start justify-between gap-3 border-b border-rose-500/20 pb-3">
                  <div>
                    <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-600 dark:text-rose-300">
                      SOFTWARE A — REPROVADO
                    </span>
                    <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100 mt-1">
                      VaultCore Internal v2.4.0
                    </h3>
                  </div>
                  <div className="text-right font-mono">
                    <div className="text-2xl font-bold text-rose-500">≤ 2.20 / 5.00</div>
                    <div className="text-[11px] text-rose-600 dark:text-rose-300">
                      Kill Switch Ativado
                    </div>
                  </div>
                </div>

                <div className="space-y-2.5 text-xs">
                  <div className="font-bold text-slate-900 dark:text-slate-100">
                    Por que foi reprovado pelo analisador?
                  </div>
                  <ul className="space-y-2 text-slate-600 dark:text-slate-300">
                    <li>
                      • <strong>Injeção de SQL (`src/db/vaultRepository.ts`)</strong>: Concatena entrada do usuário diretamente na string `SELECT * FROM credentials WHERE owner = &apos;...&apos;`.
                    </li>
                    <li>
                      • <strong>Execução Remota de Comandos (`src/sync/cloudBackup.ts`)</strong>: Invoca `child_process.execSync` interpolando caminhos não sanitizados.
                    </li>
                    <li>
                      • <strong>Criptografia Quebrada (`src/crypto/cipherEngine.ts`)</strong>: Utiliza `MD5`, cifra `AES-128-ECB` sem IV e gerador inseguro `Math.random()`.
                    </li>
                    <li>
                      • <strong>Chave Mestra Hardcoded</strong>: Contém credencial fixa no código (`VC_***`), acionando o mascaramento automático e o Kill Switch de Segurança.
                    </li>
                    <li>
                      • <strong>Arquitetura com Ciclo</strong>: Dependência circular entre módulos e violação de camada (UI importando repositório SQL diretamente).
                    </li>
                  </ul>
                </div>
              </div>

              {/* Software B: KeeSafe Open */}
              <div className="rounded-xl border border-[#31d6c4]/50 bg-[#31d6c4]/5 p-5 space-y-4">
                <div className="flex items-start justify-between gap-3 border-b border-[#31d6c4]/20 pb-3">
                  <div>
                    <span className="text-[11px] font-mono font-bold px-2 py-0.5 rounded bg-[#31d6c4]/20 text-[#0e9f8e] dark:text-[#31d6c4]">
                      SOFTWARE B — VENCEDOR TÉCNICO VALIDADO
                    </span>
                    <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100 mt-1">
                      KeeSafe Open (KeePass KDBX) v2.56.0
                    </h3>
                  </div>
                  <div className="text-right font-mono">
                    <div className="text-2xl font-bold text-emerald-600 dark:text-[#31d6c4]">
                      &gt; 4.50 / 5.00
                    </div>
                    <div className="text-[11px] text-emerald-600 dark:text-[#31d6c4]">
                      Quality Gate: OK
                    </div>
                  </div>
                </div>

                <div className="space-y-2.5 text-xs">
                  <div className="font-bold text-slate-900 dark:text-slate-100">
                    Por que venceu a comparação A/B?
                  </div>
                  <ul className="space-y-2 text-slate-600 dark:text-slate-300">
                    <li>
                      • <strong>Criptografia Autenticada Forte (`src/crypto/kdfEngine.ts`)</strong>: Usa `AES-256-GCM` com IV aleatório criptográfico (`crypto.randomBytes`) e derivação `PBKDF2-SHA512` com 600.000 iterações.
                    </li>
                    <li>
                      • <strong>Zero Vulnerabilidades SAST / Zero Segredos Expostos</strong>: Nenhuma interpolação SQL insegura, nenhum comando shell arbitrário e nenhuma chave hardcoded.
                    </li>
                    <li>
                      • <strong>Arquitetura Limpa em Camadas</strong>: Zero dependências circulares, zero violações de camada e trilha de auditoria verificada (`auditLogger.ts`).
                    </li>
                    <li>
                      • <strong>Aprovado no Quality Gate do SonarQube</strong>: Rating A (`1.0`) em Segurança, Confiabilidade e Manutenibilidade, com cobertura de testes ≥ 80%.
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* CHAPTER 4: SONARQUBE, SONARSCANNER & SARIF */}
      {activeChapter === 'sonarqube-guide' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-6 space-y-6">
            <div className="border-b border-slate-200 dark:border-slate-800 pb-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div>
                <span className="text-xs font-mono font-bold text-[#0e9f8e] dark:text-[#31d6c4]">
                  CAPÍTULO 4 — NÍVEL AVANÇADO (SONARQUBE &amp; SARIF)
                </span>
                <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100 mt-1">
                  Guia Operacional: SonarQube Community Build, SonarScanner, Cloud e SARIF
                </h2>
                <p className="text-sm text-slate-600 dark:text-slate-300 mt-1 max-w-4xl leading-relaxed">
                  Como configurar os 3 modos de operação do SonarQube, rodar os scripts oficiais de instalação com verificação SHA-256 e executar a Comparação Padronizada A/B.
                </p>
              </div>
              <button
                type="button"
                onClick={() => onNavigate('tools_integrations')}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors shrink-0 cursor-pointer"
              >
                <Wrench className="w-3.5 h-3.5" />
                <span>Abrir Tela Ferramentas e Integrações</span>
              </button>
            </div>

            {/* Official Versions & Checksums Verified */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#090d13] p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#0e9f8e] dark:text-[#31d6c4]">
                    SonarQube Community Build (Oficial)
                  </span>
                  <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-500">
                    v26.11.0.134175
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  Verificado diretamente em `binaries.sonarsource.com` (915,3 MB). Requer Java 21 (OpenJDK 21) na máquina host.
                </p>
                <div className="p-2 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800 font-mono text-[11px] break-all text-slate-700 dark:text-slate-300">
                  SHA-256: bc18bf0f9faed6d27c9668a89ab86c84b22edeccb1050fbebb9d323bd506e7dc
                </div>
              </div>

              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#090d13] p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-indigo-500 dark:text-indigo-400">
                    SonarScanner CLI (Oficial)
                  </span>
                  <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-400">
                    v8.4.0.16527
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  Scanner multiplataforma com JRE embutido para disparo de análises e importação de relatórios externos SARIF v2.1.0.
                </p>
                <div className="p-2 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800 font-mono text-[11px] break-all text-slate-700 dark:text-slate-300">
                  Linux x64 SHA-256: 2a28f118e2e9375dfd36eb27b803e1d37f93daba4db068aca6eef9853041bb24
                </div>
              </div>
            </div>

            {/* Host Scripts Copy Box */}
            <div className="space-y-3">
              <h3 className="text-sm font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Comandos Prontos para Instalação Local na Sua Máquina Host (Windows / Linux)
              </h3>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-[#090d13] p-4 text-slate-200 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-[#31d6c4] flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5" />
                      Linux / macOS (Bash)
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        handleCopyText(
                          'bash scripts/install-sonarqube.sh --install-dir ./tools/sonarqube && bash scripts/verify-sonarqube.sh',
                          'Comando Bash'
                        )
                      }
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[11px] cursor-pointer"
                    >
                      <Copy className="w-3 h-3" />
                      Copiar
                    </button>
                  </div>
                  <pre className="text-[11px] font-mono overflow-x-auto text-slate-300">
                    {`bash scripts/install-sonarqube.sh --install-dir ./tools/sonarqube\nbash scripts/verify-sonarqube.sh`}
                  </pre>
                </div>

                <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-[#090d13] p-4 text-slate-200 space-y-2">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono font-bold text-indigo-400 flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5" />
                      Windows (PowerShell)
                    </span>
                    <button
                      type="button"
                      onClick={() =>
                        handleCopyText(
                          'powershell -ExecutionPolicy Bypass -File .\\scripts\\install-sonarqube.ps1',
                          'Comando PowerShell'
                        )
                      }
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[11px] cursor-pointer"
                    >
                      <Copy className="w-3 h-3" />
                      Copiar
                    </button>
                  </div>
                  <pre className="text-[11px] font-mono overflow-x-auto text-slate-300">
                    {`powershell -ExecutionPolicy Bypass -File .\\scripts\\install-sonarqube.ps1`}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* CHAPTER 5: GITAR AI & SECURITY SUITE */}
      {activeChapter === 'gitar-security-guide' && (
        <div className="space-y-6">
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-6 space-y-6">
            <div className="border-b border-slate-200 dark:border-slate-800 pb-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div>
                <span className="text-xs font-mono font-bold text-[#0e9f8e] dark:text-[#31d6c4]">
                  CAPÍTULO 5 — NÍVEL AVANÇADO (GITAR AI &amp; SUÍTE DE SEGURANÇA)
                </span>
                <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100 mt-1">
                  Revisão Assistida com Gitar AI (Branch Isolada) &amp; Suíte de 21 Adaptadores
                </h2>
                <p className="text-sm text-slate-600 dark:text-slate-300 mt-1 max-w-4xl leading-relaxed">
                  Entenda como o Gitar AI analisa Pull Requests e falhas de CI sem tocar nos arquivos originais e como inspecionar a Superfície de Ataque dos softwares.
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => onNavigate('tools_integrations')}
                  className="px-3.5 py-2 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:border-[#31d6c4] transition-colors cursor-pointer"
                >
                  Abrir Gitar AI
                </button>
                <button
                  type="button"
                  onClick={() => onNavigate('security_suite')}
                  className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                >
                  Abrir Suíte de Segurança
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#090d13] p-5 space-y-3">
                <div className="flex items-center gap-2 text-xs font-mono font-bold text-[#0e9f8e] dark:text-[#31d6c4]">
                  <Code2 className="w-4 h-4" />
                  <span>AI CODE REVIEW &amp; REMEDIATION (GITAR AI)</span>
                </div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Fluxo de Aprovação Humana em 4 Etapas Seguras
                </h3>
                <ol className="space-y-2 text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                  <li>
                    <strong>1. Estado Inicial Honesto (`NOT_CONFIGURED`)</strong>: O Gitar AI jamais simula atividade sem configuração ou autorização explícita.
                  </li>
                  <li>
                    <strong>2. Deduplicação contra SonarQube</strong>: Quando um achado de Pull Request coincide com uma issue já reportada pelo SonarQube no mesmo arquivo/linha, o `GitarReviewMapper` correlaciona ambos para evitar dupla contagem.
                  </li>
                  <li>
                    <strong>3. Patch em Branch Isolada (`gitar/remediation-isolated/*`)</strong>: O código-fonte original dos Softwares A e B permanece 100% intocado em modo somente-leitura.
                  </li>
                  <li>
                    <strong>4. Deliberação Humana (`Aprovar` ou `Rejeitar`)</strong>: Você inspeciona o diff Antes/Depois na tela e decide se aprova a correção na branch isolada (disparando o re-teste automatizado) ou se rejeita o patch.
                  </li>
                </ol>
              </div>

              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#090d13] p-5 space-y-3">
                <div className="flex items-center gap-2 text-xs font-mono font-bold text-rose-500">
                  <ShieldCheck className="w-4 h-4" />
                  <span>SUÍTE DE SEGURANÇA (15 MÓDULOS &amp; 21 ADAPTADORES)</span>
                </div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Como interpretar os 6 Estados de Validação de Vulnerabilidades
                </h3>
                <div className="space-y-1.5 text-xs">
                  <div className="p-2 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                    <strong className="text-rose-500 font-mono">CONFIRMADA</strong>: Evidência direta encontrada na AST/código com caminho de exploração reproduzível.
                  </div>
                  <div className="p-2 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                    <strong className="text-amber-500 font-mono">PROVAVEL</strong>: Padrão vulnerável detectado, dependente de configuração de runtime.
                  </div>
                  <div className="p-2 rounded bg-white dark:bg-[#0f141c] border border-slate-200 dark:border-slate-800">
                    <strong className="text-emerald-500 font-mono">FALSO_POSITIVO / NAO_REPRODUZIVEL</strong>: Mitigação ou sanitização verificada na camada anterior.
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* CHAPTER 6: GLOSSARY & FAQ */}
      {activeChapter === 'glossary-faq' && (
        <div className="space-y-6">
          {/* Searchable Technical Glossary */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-6 space-y-5">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
              <div>
                <span className="text-xs font-mono font-bold text-[#0e9f8e] dark:text-[#31d6c4]">
                  CAPÍTULO 6 — DICIONÁRIO TÉCNICO &amp; PERGUNTAS FREQUENTES
                </span>
                <h2 className="text-xl font-bold text-slate-900 dark:text-slate-100 mt-1">
                  Glossário de Siglas, Métricas e Conceitos ({filteredGlossary.length} termos)
                </h2>
              </div>

              <div className="flex flex-wrap items-center gap-1.5">
                {[
                  'TODOS',
                  'Pontuação & Matemática',
                  'Segurança & DevSecOps',
                  'SonarQube & SARIF',
                  'Gitar AI & CI',
                  'Arquitetura & Performance',
                ].map((cat) => (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => setSelectedGlossaryCategory(cat)}
                    className={`px-2.5 py-1 rounded-md text-xs font-semibold transition-colors cursor-pointer ${
                      selectedGlossaryCategory === cat
                        ? 'bg-[#31d6c4] text-slate-950'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-200 dark:hover:bg-slate-700'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredGlossary.map((item) => (
                <div
                  key={item.term}
                  className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#090d13] p-4 space-y-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-sm font-bold font-mono text-[#0e9f8e] dark:text-[#31d6c4]">
                      {item.term}
                    </h3>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-200/70 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                      {item.category}
                    </span>
                  </div>
                  <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed">
                    {item.simpleExplanation}
                  </p>
                  <div className="pt-2 border-t border-slate-200/70 dark:border-slate-800/70 text-[11px] text-slate-500 dark:text-slate-400">
                    <strong className="text-slate-700 dark:text-slate-200">
                      Impacto na Comparação A/B:
                    </strong>{' '}
                    {item.practicalImpactAB}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* FAQ Section */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-6 space-y-4">
            <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <HelpCircle className="w-5 h-5 text-[#31d6c4]" />
              <span>Perguntas Frequentes (FAQ Operacional)</span>
            </h3>
            <div className="space-y-3">
              {filteredFaq.map((faq) => (
                <div
                  key={faq.q}
                  className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-[#090d13] p-4 space-y-1.5"
                >
                  <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                    {faq.q}
                  </h4>
                  <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
                    {faq.a}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
