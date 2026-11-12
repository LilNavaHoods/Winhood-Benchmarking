import React, { useState } from 'react';
import {
  BookOpen,
  ChevronDown,
  ChevronUp,
  Compass,
  HelpCircle,
  Info,
  Lightbulb,
  ListChecks,
} from 'lucide-react';
import type { AppNavSection } from './StepByStepJourneyBar';

interface ScreenGuideContent {
  stepBadge: string;
  screenTitle: string;
  plainSummary: string;
  howToSteps: [string, string, string];
  abInterpretationTip: string;
  guideChapterId: string;
  guideChapterLabel: string;
  glossaryTerms: Array<{
    term: string;
    meaning: string;
  }>;
}

const SCREEN_HELP_CATALOG: Record<Exclude<AppNavSection, 'user_guide'>, ScreenGuideContent> = {
  dashboard: {
    stepBadge: 'VISÃO EXECUTIVA CENTRAL',
    screenTitle: 'Como entender o Dashboard Central',
    plainSummary:
      'Esta tela resume toda a avaliação comparativa entre o Software A e o Software B em notas de 0.00 a 5.00, destacando quem venceu tecnicamente e se alguma trava de segurança crítica (Kill Switch) foi acionada.',
    howToSteps: [
      '1. Se o ambiente estiver vazio, clique em "Carregar e Analisar Repositórios Reais" para ver um comparativo A/B completo imediatamente.',
      '2. Compare os cartões lado a lado do Software A e do Software B: notas verdes (≥ 4.00) indicam maturidade alta; notas vermelhas (< 3.00) indicam bloqueio por falha grave.',
      '3. Verifique a caixa "Travas Matemáticas (Kill Switches)" em cada software para entender se uma falha crítica limitou a nota máxima.',
    ],
    abInterpretationTip:
      'Mesmo que um software tenha boa aparência ou recursos visuais, se ele tiver SQL Injection ou chave secreta exposta no código, o Kill Switch trava sua nota geral em no máximo 2.20 / 5.00 para impedir uma aprovação insegura.',
    guideChapterId: 'ab-case-study',
    guideChapterLabel: 'Estudo Prático A/B e Notas',
    glossaryTerms: [
      {
        term: 'Escala 0.00 a 5.00',
        meaning: 'Pontuação determinística calculada sobre código real (5.00 = Excelente, < 3.00 = Reprovado por risco técnico).',
      },
      {
        term: 'Kill Switch (Penalty Cap)',
        meaning: 'Trava matemática automática que limita a nota máxima se houver vulnerabilidade crítica ou segredo hardcoded.',
      },
      {
        term: 'Evidências SHA-256',
        meaning: 'Assinatura criptográfica imutável que comprova que a análise foi feita nos arquivos reais e não foi adulterada.',
      },
    ],
  },
  projects: {
    stepBadge: 'PASSO 1 DA JORNADA',
    screenTitle: 'Como cadastrar Projetos e Softwares (A e B)',
    plainSummary:
      'Aqui você cria o projeto de comparação e adiciona os softwares concorrentes (Software A e Software B) enviando arquivos locais (Upload), pesquisando repositórios públicos no GitHub ou cadastrando manualmente.',
    howToSteps: [
      '1. Crie ou selecione um Projeto de Avaliação (ex.: "Avaliação de Cofres de Senhas Corporativos").',
      '2. Clique em "Upload de Código" ou "Buscar no GitHub" no topo para importar os arquivos reais dos softwares que deseja comparar.',
      '3. Confira o Inventário Técnico gerado automaticamente (total de arquivos, linhas de código LOC, linguagens e hash SHA-256).',
    ],
    abInterpretationTip:
      'Para uma comparação A/B justa, certifique-se de que ambos os softwares pertencem ao mesmo projeto e possuem seus arquivos de código-fonte carregados.',
    guideChapterId: 'quickstart',
    guideChapterLabel: 'Início Rápido & Cadastro de Softwares',
    glossaryTerms: [
      {
        term: 'Inventário Técnico',
        meaning: 'Contagem real de arquivos, linhas de código (LOC) e distribuição de linguagens extraída diretamente dos arquivos.',
      },
      {
        term: 'Hash do Pacote (SHA-256)',
        meaning: 'Impressão digital única de toda a árvore de código do software avaliado.',
      },
      {
        term: 'Isolamento de Workspace',
        meaning: 'Cada software é analisado de forma independente, sem misturar dependências ou arquivos.',
      },
    ],
  },
  wizard: {
    stepBadge: 'PASSO 2 DA JORNADA',
    screenTitle: 'Como configurar Pesos e Executar o Benchmark A/B',
    plainSummary:
      'O Wizard permite escolher quais softwares serão comparados, ajustar os pesos das 12 categorias de qualidade (cuja soma deve ser exatamente 100%) e disparar a análise estática e arquitetural real.',
    howToSteps: [
      '1. Selecione o Projeto, o Perfil de Avaliação e marque os Softwares A e B que participarão da rodada.',
      '2. Ajuste os pesos das categorias (Segurança, Qualidade, Arquitetura, Desempenho, etc.) mantendo a soma total em exatos 100%.',
      '3. Preencha os parâmetros de equivalência de ambiente (CPU, RAM, SO) e clique em "Executar Benchmark Determinístico Real".',
    ],
    abInterpretationTip:
      'Se a sua empresa prioriza Segurança acima de tudo, aumente o peso de Segurança & Criptografia (ex.: 30%) e reduza categorias secundárias mantendo o total em 100%.',
    guideChapterId: 'benchmark-weights',
    guideChapterLabel: 'Pesos Matemáticos & Equivalência',
    glossaryTerms: [
      {
        term: 'Soma Exata de 100%',
        meaning: 'Validação matemática obrigatória para que nenhuma categoria distorça a média ponderada final.',
      },
      {
        term: 'Condições de Equivalência',
        meaning: 'Garantia de que os Softwares A e B foram avaliados sob os mesmos limites de CPU, memória e regras.',
      },
      {
        term: 'DAST Autorizado',
        meaning: 'Testes dinâmicos ativos só são liberados quando há confirmação explícita de autorização do proprietário.',
      },
    ],
  },
  market_discovery: {
    stepBadge: 'MODALIDADE C — PESQUISA DE MERCADO',
    screenTitle: 'Como descobrir e homologar o Concorrente de Mercado mais próximo',
    plainSummary:
      'O Motor de Descoberta de Concorrentes analisa o propósito, funcionalidades e arquitetura do seu software contra o catálogo de referência de mercado, calculando a similaridade ponderada em 6 eixos e exigindo aprovação humana antes da comparação.',
    howToSteps: [
      '1. Selecione a Modalidade C (Descobrir Concorrente de Mercado) no Passo 1 do Wizard.',
      '2. Selecione o seu software principal no Passo 2 e avance para o Passo 3 para visualizar os candidatos do mercado ranqueados por similaridade.',
      '3. Revise o detalhamento de similaridade (Propósito 30%, Funcionalidades 25%, Público 15%, Plataforma 10%, Distribuição 10%, Integrações 10%) e clique em "Homologar e Aprovar Concorrente".',
    ],
    abInterpretationTip:
      'O motor diferencia concorrentes Open-Source (varredura completa de código fonte) de concorrentes Closed-Source / Proprietários (avaliação baseada em documentação pública e APIs oficiais).',
    guideChapterId: 'benchmark-weights',
    guideChapterLabel: 'Pesquisa de Mercado & Equivalência',
    glossaryTerms: [
      {
        term: 'Similaridade Ponderada (6 Eixos)',
        meaning: 'Algoritmo determinístico que cruza finalidade (30%), recursos (25%), público (15%), plataforma (10%), distribuição (10%) e integrações (10%).',
      },
      {
        term: 'Homologação Humana (HITL)',
        meaning: 'Regra mandatória que impede comparações automáticas de mercado sem aprovação explícita do analista.',
      },
    ],
  },
  sonar_hub: {
    stepBadge: 'SONAR HUB & DOCKER',
    screenTitle: 'Como usar SonarQube Local via Docker, SonarCloud e Hardware Multi-Core',
    plainSummary:
      'Guia oficial para executar o SonarQube via container Docker sem necessidade de rodar localmente no sistema, conectar ao SonarCloud na nuvem e configurar a aceleração por múltiplos núcleos de CPU para testes pesados.',
    howToSteps: [
      '1. Na aba "Opção A: SonarQube Local", copie o comando oficial Docker e suba o container na porta 9000 com 1 clique.',
      '2. Acesse http://localhost:9000, faça login inicial com admin / admin e crie seu projeto para obter o token de acesso.',
      '3. Na aba "Gerador SonarScanner", selecione sua stack (Node.js, Maven, Gradle, .NET) e copie o comando pronto para execução.',
    ],
    abInterpretationTip:
      'Utilizar o Docker oficial isola o SonarQube em container descartável, permitindo atingir notas altas de Quality Gate sem sujar a máquina física com arquivos zip gigantes ou JDK 17 manual.',
    guideChapterId: 'sonarqube-guide',
    guideChapterLabel: 'SonarQube Docker & Cloud',
    glossaryTerms: [
      {
        term: 'Docker Oficial SonarQube',
        meaning: 'Container oficial (sonarqube:latest) que roda isoladamente na porta 9000 sem downloads manuais pesados no SO.',
      },
      {
        term: 'SonarCloud',
        meaning: 'Plataforma oficial da Sonar em nuvem que analisa commits e pull requests diretamente via GitHub/GitLab sem usar recursos locais.',
      },
      {
        term: 'Worker Threads Multi-Core',
        meaning: 'Distribuição paralela das análises em múltiplos núcleos de CPU para acelerar testes pesados em grandes bases de código.',
      },
    ],
  },
  tools_integrations: {
    stepBadge: 'PASSO 3 DA JORNADA',
    screenTitle: 'Como usar SonarQube, SonarScanner, SARIF e Gitar AI',
    plainSummary:
      'Conecta o analisador ao ecossistema SonarQube (Servidor Local, Servidor Remoto ou SonarQube Cloud) e ao Gitar AI para revisão assistida de Pull Requests e falhas de CI com aprovação humana obrigatória.',
    howToSteps: [
      '1. Na aba "Comparação Padronizada A/B (SonarQube)", clique em "Executar Comparação A/B Padronizada" para avaliar os Softwares A e B sob o mesmo Quality Gate.',
      '2. Na aba "Gitar AI Code Review & CI", clique em "Executar Validação de Contrato Gitar AI" e aprove ou rejeite os patches propostos em branch isolada.',
      '3. Na aba "Suíte de 27 Testes de Integração", execute a bateria real de 15 testes principais + 12 testes de injeção de falha.',
    ],
    abInterpretationTip:
      'Esta tela separa claramente o que é "Métrica Nativa do SonarQube", o que é "Calculado pelo Benchmark Analyzer" e o que veio de "Relatório Externo SARIF Importado", evitando dupla contagem.',
    guideChapterId: 'sonarqube-guide',
    guideChapterLabel: 'SonarQube, SARIF & Gitar AI',
    glossaryTerms: [
      {
        term: 'Quality Gate (OK / ERROR)',
        meaning: 'Critério oficial do SonarQube que aprova (OK) ou reprova (ERROR) o código com base em vulnerabilidades, cobertura e duplicação.',
      },
      {
        term: 'SARIF v2.1.0',
        meaning: 'Formato padrão internacional para importar achados de ferramentas externas (Semgrep, Gitleaks, Trivy) sem duplicar issues.',
      },
      {
        term: 'Branch Isolada (Gitar AI)',
        meaning: 'Patches sugeridos pela IA ficam isolados em branch separada e exigem aprovação humana, nunca alterando o código original.',
      },
    ],
  },
  security_suite: {
    stepBadge: 'PASSO 4A DA JORNADA',
    screenTitle: 'Como inspecionar a Suíte de Segurança & Resiliência',
    plainSummary:
      'Apresenta os 15 módulos de avaliação profunda de segurança, os 21 adaptadores técnicos, o mapeamento da Superfície de Ataque exposta e os Caminhos de Ataque (Attack Paths) reproduzíveis entre os Softwares A e B.',
    howToSteps: [
      '1. Compare o "Índice de Risco de Superfície" e a "Maturidade Geral de Segurança" entre o Software A e o Software B no topo.',
      '2. Navegue pelas sub-abas para inspecionar Superfície de Ataque (endpoints, portas, conectores SQL) e Cadeias de Exploração (Attack Paths).',
      '3. Verifique o estado de validação de cada vulnerabilidade (CONFIRMADA, PROVÁVEL, FALSO_POSITIVO) com histórico de reexecução.',
    ],
    abInterpretationTip:
      'Foque primeiro nos achados com estado "CONFIRMADA" e facilidade de reprodução "ALTA": eles representam riscos imediatos de invasão ou vazamento de dados no software avaliado.',
    guideChapterId: 'gitar-security-guide',
    guideChapterLabel: 'Suíte de Segurança & Superfície de Ataque',
    glossaryTerms: [
      {
        term: 'Superfície de Ataque',
        meaning: 'Todos os pontos de entrada expostos pelo software (rotas HTTP, comandos CLI, queries SQL e arquivos de configuração).',
      },
      {
        term: 'Attack Path (Cadeia de Ataque)',
        meaning: 'Sequência passo a passo mostrando como um invasor explora uma falha desde a entrada até o impacto crítico.',
      },
      {
        term: 'Estado de Validação (6 níveis)',
        meaning: 'Classificação rigorosa: CONFIRMADA, PROVÁVEL, FALSO_POSITIVO, NÃO_REPRODUZÍVEL, INCONCLUSIVA ou NÃO_TESTADA.',
      },
    ],
  },
  findings: {
    stepBadge: 'PASSO 4B DA JORNADA',
    screenTitle: 'Como auditar Achados de Código & DevSecOps',
    plainSummary:
      'Lista todas as vulnerabilidades e problemas de código encontrados línea por linha (SAST, Segredos Vazados, Dependências SCA, Banco de Dados SQL e Qualidade), com trecho de código real e recomendação de correção.',
    howToSteps: [
      '1. Use os filtros por Software, Severidade (CRITICAL, HIGH, MEDIUM, LOW) ou Categoria (SAST, SECRETS, SCA, SQL) para focar nos problemas mais graves.',
      '2. Analise o trecho de código evidenciado (com segredos sensíveis automaticamente mascarados por segurança) e o identificador CWE / OWASP.',
      '3. Siga a instrução prática em "Recomendação de Mitigação" para corrigir a falha na origem.',
    ],
    abInterpretationTip:
      'Compare a quantidade de achados CRITICAL e HIGH entre o Software A e o Software B. Um único segredo exposto (SECRETS) ou injeção de comando (SAST) compromete toda a segurança do produto.',
    guideChapterId: 'ab-case-study',
    guideChapterLabel: 'Achados SAST, Segredos & Mitigação',
    glossaryTerms: [
      {
        term: 'SAST',
        meaning: 'Static Application Security Testing — análise do código-fonte em busca de falhas como SQL Injection, RCE e criptografia fraca.',
      },
      {
        term: 'SCA',
        meaning: 'Software Composition Analysis — verificação de bibliotecas e pacotes de terceiros com vulnerabilidades conhecidas (CVEs).',
      },
      {
        term: 'Mascaramento de Segredos',
        meaning: 'Redação automática de chaves e senhas reais encontradas no código (ex.: VC_***) para evitar vazamento nos relatórios.',
      },
    ],
  },
  arch_qa_perf: {
    stepBadge: 'PASSO 4C DA JORNADA',
    screenTitle: 'Como avaliar Arquitetura, QA, Banco de Dados & Performance',
    plainSummary:
      'Examina a estrutura interna dos softwares: grafo de dependências entre módulos, ciclos arquiteturais, violações de camadas, cobertura de testes (QA), eficiência de banco de dados e latência/throughput.',
    howToSteps: [
      '1. Verifique se existem "Dependências Circulares" ou "Violações de Camada" (ex.: camada de interface acessando banco SQL diretamente).',
      '2. Compare a Complexidade Ciclomática, Dívida Técnica (em minutos) e Cobertura de Testes Automatizados entre os Softwares A e B.',
      '3. Analise os indicadores de Desempenho (Latência P95, Throughput RPS e consumo de CPU/Memória) e compatibilidade de Sistema Operacional.',
    ],
    abInterpretationTip:
      'Softwares com zero dependências circulares, baixa complexidade ciclomática (< 10) e alta cobertura de testes (≥ 80%) custam muito menos para manter e atualizar a longo prazo.',
    guideChapterId: 'benchmark-weights',
    guideChapterLabel: 'Arquitetura, Complexidade & Performance',
    glossaryTerms: [
      {
        term: 'Dependência Circular',
        meaning: 'Quando o Módulo A depende do Módulo B e o Módulo B depende de volta do Módulo A, dificultando manutenção e testes.',
      },
      {
        term: 'Violação de Camada',
        meaning: 'Quebra da separação arquitetural (ex.: um componente visual executando comandos diretos de banco de dados).',
      },
      {
        term: 'Complexidade Ciclomática',
        meaning: 'Mede a quantidade de caminhos lógicos (if/else/loops) por função; valores altos aumentam o risco de bugs.',
      },
    ],
  },
  hardware_benchmark: {
    stepBadge: 'PASSO 4D DA JORNADA',
    screenTitle: 'Como avaliar Hardware, GPU, IOPS e Calibração Óptica de Monitores',
    plainSummary:
      'Executa micro-benchmarks determinísticos da estação de trabalho (CPU Single/Multi-Core, Banda de Memória Float64, IOPS de Disco 4K) e diagnóstico óptico interativo do monitor (Taxa de Atualização Real Hz, Jitter, Ghosting UFO, Dead Pixels e Uniformidade DSE).',
    howToSteps: [
      '1. Clique em "Executar Benchmark de Hardware" no topo para medir CPU SHA-256, multiplicação matricial MFLOPS, banda de RAM e IOPS 4K reais do host com hash SHA-256.',
      '2. Clique em "Medir Hz & Jitter" para amostrar a cadência real de quadros via requestAnimationFrame (FPS médio, 1% Low, 0.1% Low e estabilidade).',
      '3. Utilize o Laboratório Visual Interativo (Motion UFO, Inspeção de Dead Pixel em Tela Cheia, Rampa de Gradiente 256-steps e Latência Reflex) e anexe o snapshot a um BenchmarkRun.',
    ],
    abInterpretationTip:
      'Anexar o snapshot de Hardware & Display ao BenchmarkRun garante rastreabilidade completa da infraestrutura física onde os testes de performance e compilação SAST foram executados.',
    guideChapterId: 'benchmark-weights',
    guideChapterLabel: 'Equivalência de Hardware & Telemetria',
    glossaryTerms: [
      {
        term: '1% Low & Frame Jitter',
        meaning: 'Mede a consistência temporal dos quadros (ms); quedas bruscas no 1% Low indicam micro-stuttering visual.',
      },
      {
        term: 'PPI & Dot Pitch (mm)',
        meaning: 'Densidade de pixels por polegada e distância física entre subpixels, determinando a nitidez tipográfica (Retina/HiDPI).',
      },
      {
        term: 'IOPS 4K & Banda Float64',
        meaning: 'Velocidade real de leitura/escrita aleatória em disco e vazão de memória RAM em megabytes por segundo.',
      },
    ],
  },
  veracity: {
    stepBadge: 'PASSO 5 DA JORNADA',
    screenTitle: 'Como auditar o Motor de Veracidade & Adaptadores',
    plainSummary:
      'Comprova que nenhuma nota ou métrica foi inventada: exibe a classificação de veracidade de cada etapa, o status real de instalação de cada ferramenta no sistema operacional e a cadeia de evidências SHA-256.',
    howToSteps: [
      '1. Confira o cartão de Veracidade de cada software para confirmar o status "SUCCESS_VALIDATED" e a porcentagem de cobertura real.',
      '2. Na tabela de Adaptadores de Ferramentas, veja quais motores estão "OPERATIONAL" no container atual e quais estão "FERRAMENTA NÃO INSTALADA".',
      '3. Audite a Trilha de Auditoria (Audit Log) e os hashes SHA-256 de entrada e saída de cada execução.',
    ],
    abInterpretationTip:
      'Esta tela é a garantia para auditores e diretores: toda pontuação exibida no sistema possui rastreabilidade até o arquivo, linha e hash criptográfico real.',
    guideChapterId: 'glossary-faq',
    guideChapterLabel: 'Veracidade, Hashes SHA-256 & Auditoria',
    glossaryTerms: [
      {
        term: 'SUCCESS_VALIDATED',
        meaning: 'Indica que a análise foi executada até o fim sobre arquivos reais e validada sem erros de integridade.',
      },
      {
        term: 'Status Honesto de Binários',
        meaning: 'Ferramentas ausentes no SO nunca são simuladas como instaladas; o sistema informa seu estado real com transparência.',
      },
      {
        term: 'Cadeia de Evidências',
        meaning: 'Lista imutável de artefatos gerados na análise, cada um assinado com SHA-256.',
      },
    ],
  },
  reports: {
    stepBadge: 'PASSO 6 DA JORNADA',
    screenTitle: 'Como gerar e exportar Relatórios Técnicos & Laudos A/B',
    plainSummary:
      'Consolida o parecer técnico final da comparação A/B com recomendação executiva, tabelas comparativas completas e exportação imediata nos formatos JSON, Markdown (.md) e HTML/PDF para impressão.',
    howToSteps: [
      '1. Revise o Parecer Executivo e a tabela comparativa consolidada dos Softwares A e B.',
      '2. Clique em "Exportar JSON", "Exportar Markdown" ou "Exportar Relatório HTML / Imprimir PDF" para baixar o laudo oficial.',
      '3. Compartilhe o relatório assinado com hashes SHA-256 com sua equipe de arquitetura, compras ou segurança.',
    ],
    abInterpretationTip:
      'Use o formato HTML/PDF para apresentações executivas à diretoria e o formato Markdown/JSON para anexar em Pull Requests, wikis técnicas ou pipelines de auditoria.',
    guideChapterId: 'ab-case-study',
    guideChapterLabel: 'Exportação de Laudos & Decisão Final',
    glossaryTerms: [
      {
        term: 'Laudo Determinístico',
        meaning: 'Relatório onde os mesmos arquivos de entrada e mesmos pesos produzem exatamente o mesmo resultado em qualquer auditoria.',
      },
      {
        term: 'Vencedor Técnico Validado',
        meaning: 'Software que obteve a maior nota ponderada global sem acionar travas eliminatórias de segurança.',
      },
    ],
  },
};

interface ContextualScreenHelpBannerProps {
  activeNav: AppNavSection;
  onOpenGuideChapter: (chapterId: string) => void;
}

export const ContextualScreenHelpBanner: React.FC<ContextualScreenHelpBannerProps> = ({
  activeNav,
  onOpenGuideChapter,
}) => {
  const [isExpanded, setIsExpanded] = useState<boolean>(false);

  if (activeNav === 'user_guide') {
    return null;
  }

  const content = SCREEN_HELP_CATALOG[activeNav];
  if (!content) return null;

  const toggleExpanded = () => {
    setIsExpanded((prev) => {
      const next = !prev;
      try {
        localStorage.setItem('winhood_contextual_help_expanded', String(next));
      } catch {
        // Ignore storage error
      }
      return next;
    });
  };

  return (
    <div className="mb-6 rounded-xl border border-slate-200 dark:border-slate-800/90 bg-white dark:bg-[#0d121a] overflow-hidden shadow-xs">
      {/* Compact Header Bar */}
      <div className="px-4 py-2.5 bg-slate-50/80 dark:bg-[#101722] flex flex-wrap items-center justify-between gap-3 border-b border-slate-200/70 dark:border-slate-800/70">
        <div className="flex items-center gap-2.5 min-w-0">
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#31d6c4]/15 text-[#0e9f8e] dark:text-[#31d6c4] border border-[#31d6c4]/30 shrink-0">
            <Compass className="w-3 h-3" />
            {content.stepBadge}
          </span>
          <h2 className="text-xs sm:text-sm font-bold text-slate-900 dark:text-slate-100 truncate">
            {content.screenTitle}
          </h2>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => onOpenGuideChapter(content.guideChapterId)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold text-[#0e9f8e] dark:text-[#31d6c4] hover:bg-[#31d6c4]/10 transition-colors cursor-pointer"
          >
            <BookOpen className="w-3.5 h-3.5" />
            <span>Ver no Guia: {content.guideChapterLabel}</span>
          </button>

          <button
            type="button"
            onClick={toggleExpanded}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <HelpCircle className="w-3.5 h-3.5 text-[#31d6c4]" />
            <span>{isExpanded ? 'Ocultar Dicas da Tela' : 'Como Usar Esta Tela'}</span>
            {isExpanded ? (
              <ChevronUp className="w-3.5 h-3.5" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5" />
            )}
          </button>
        </div>
      </div>

      {/* Expandable Body */}
      {isExpanded && (
        <div className="p-4 space-y-4 text-xs">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Column 1: What this screen does & A/B Tip */}
            <div className="space-y-2.5 rounded-lg border border-slate-200/80 dark:border-slate-800/80 bg-slate-50/50 dark:bg-[#090d13] p-3.5">
              <div className="flex items-center gap-1.5 font-bold text-slate-900 dark:text-slate-100">
                <Info className="w-4 h-4 text-[#31d6c4] shrink-0" />
                <span>Para que serve esta tela?</span>
              </div>
              <p className="text-slate-600 dark:text-slate-300 leading-relaxed">
                {content.plainSummary}
              </p>
              <div className="pt-2 border-t border-slate-200/70 dark:border-slate-800/70 flex items-start gap-2 text-amber-700 dark:text-amber-300">
                <Lightbulb className="w-4 h-4 shrink-0 mt-0.5 text-amber-500" />
                <span>
                  <strong>Dica de Decisão A/B:</strong> {content.abInterpretationTip}
                </span>
              </div>
            </div>

            {/* Column 2: 3-Step Quick Instructions */}
            <div className="space-y-2 rounded-lg border border-slate-200/80 dark:border-slate-800/80 bg-slate-50/50 dark:bg-[#090d13] p-3.5">
              <div className="flex items-center gap-1.5 font-bold text-slate-900 dark:text-slate-100">
                <ListChecks className="w-4 h-4 text-[#31d6c4] shrink-0" />
                <span>Passo a Passo Rápido nesta Tela</span>
              </div>
              <ul className="space-y-2 text-slate-600 dark:text-slate-300 leading-relaxed">
                {content.howToSteps.map((stepText, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="w-4 h-4 rounded-full bg-[#31d6c4]/15 text-[#0e9f8e] dark:text-[#31d6c4] font-mono font-bold text-[10px] flex items-center justify-center shrink-0 mt-0.5">
                      {idx + 1}
                    </span>
                    <span>{stepText.replace(/^[0-9]+\.\s*/, '')}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Column 3: Quick Glossary of Terms on this Screen */}
            <div className="space-y-2 rounded-lg border border-slate-200/80 dark:border-slate-800/80 bg-slate-50/50 dark:bg-[#090d13] p-3.5">
              <div className="flex items-center justify-between gap-2 font-bold text-slate-900 dark:text-slate-100">
                <span>Glossário Rápido da Tela</span>
                <button
                  type="button"
                  onClick={() => onOpenGuideChapter('glossary-faq')}
                  className="text-[11px] font-semibold text-[#0e9f8e] dark:text-[#31d6c4] hover:underline cursor-pointer"
                >
                  Glossário Completo →
                </button>
              </div>
              <div className="space-y-2">
                {content.glossaryTerms.map((item) => (
                  <div
                    key={item.term}
                    className="rounded border border-slate-200/70 dark:border-slate-800 bg-white dark:bg-[#0f141c] px-2.5 py-1.5"
                  >
                    <div className="font-mono font-bold text-[11px] text-[#0e9f8e] dark:text-[#31d6c4]">
                      {item.term}
                    </div>
                    <div className="text-[11px] text-slate-600 dark:text-slate-400 leading-snug mt-0.5">
                      {item.meaning}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
