# WinHood Analyzer — Progresso Global em Tempo Real, Motor Equivalente/Superior ao SonarQube e Higienização para GitHub

Atualização arquitetural da plataforma WinHood Analyzer para incluir um monitor global de **Progresso de Análise** com estimativa de tempo restante (ETA) no cabeçalho durante execuções em andamento, eliminar qualquer repositório ou estado mocado inicial, elevar a profundidade do motor de análise estática e segurança ao padrão SonarQube + SARIF 2.1.0, e tornar o repositório enxuto e pronto para versionamento no GitHub.

## User Review & Critical Decisions

> [!IMPORTANT]
> As decisões abaixo refletem exatamente as escolhas confirmadas na etapa de alinhamento:

- **Decisão Confirmada 1 — Estado Inicial 100% Real (Zero Dados Mocados)**: A plataforma iniciará com banco de dados limpo (zero projetos ou softwares fictícios pré-carregados). Toda avaliação partirá exclusivamente de projetos reais enviados via Upload Local de arquivos/pastas ou importados diretamente da API oficial do GitHub (buscando a árvore real de código-fonte do repositório via API Git Trees/Contents do GitHub, sem stubs estáticos).
- **Decisão Confirmada 2 — Exportação Multi-Formato Compatível com SonarQube e GitHub**: Suporte nativo de exportação de laudos e achados em **JSON Completo**, **SARIF 2.1.0** (compatível com GitHub Code Scanning e SonarQube External Issues), **HTML Interativo Autônomo**, **Relatório Markdown** e **Planilha CSV/Excel**.
- **Decisão Confirmada 3 — Repositório Leve e Pronto para GitHub**: Remoção de arquivos binários/zips pesados desnecessários, limpeza de artefatos temporários preexistentes e blindagem do controle de versão para manter o projeto leve, rápido e fácil de publicar no GitHub.

---

## 1. Overview & Core Concept

- **What It Does**:
  1. **Componente Visual Global de Progresso de Análise (`AnalysisProgressHeaderBanner`)**: Posicionado no cabeçalho global da aplicação, monitora execuções com status `RUNNING` (em andamento), exibindo barra de progresso animada de alta precisão, percentual concluído, etapa/ferramenta ativa, contador de arquivos inspecionados e **Tempo Estimado de Conclusão (ETA)** atualizado em tempo real, além de botão de cancelamento emergencial.
  2. **Ingestão 100% Real (Zero Mock)**: Ao importar um repositório do GitHub ou fazer upload de arquivos locais, o backend baixa e processa os arquivos reais do repositório (via GitHub REST API) ou do pacote enviado, calculando hashes criptográficos SHA-256 reais sobre cada arquivo.
  3. **Motor de Qualidade e Segurança Equivalente/Superior ao SonarQube**: Avalia regras profundas de SAST, Secrets, SCA/SBOM, SQL, Arquitetura (acoplamento aferente/eferente, instabilidade e ciclos) e Qualidade estilo SonarQube (Ratings `A` a `E` de Confiabilidade, Segurança e Manutenibilidade, cálculo de Dívida Técnica em minutos, Densidade de Duplicação, Complexidade Ciclomática e Cognitiva por função, Security Hotspots e Quality Gate `PASSED`/`FAILED` com condições auditáveis).
  4. **Exportação Universal de Documentos**: Geração imediata de relatórios em `JSON`, `SARIF 2.1.0`, `HTML`, `Markdown` e `CSV`.
- **Target Audience / Persona**: Engenheiros de Segurança (AppSec/DevSecOps), Arquitetos de Software e Líderes de QA que necessitam comparar ou auditar projetos reais com rastreabilidade criptográfica e exportar laudos diretamente para pipelines GitHub/SonarQube.
- **Key Value**: Transparência operacional durante análises de múltiplos estágios, confiabilidade forense livre de dados simulados e portabilidade imediata do código para o GitHub.

---

## 2. User Experience & Visual Design

- **Key User Flows**:
  1. **Zero-State Limpo & Ingestão Real**: Ao abrir a plataforma sem avaliações prévias, o usuário visualiza o estado vazio claro com ações diretas para **Upload de Código Local** ou **Importação Real via GitHub API**.
  2. **Execução Assíncrona com Progresso Global e ETA**: Ao iniciar um benchmark no Wizard (ou reexecutar uma avaliação), a corrida entra no estado `RUNNING` (`em andamento`). Imediatamente, o cabeçalho global exibe o componente **Progresso de Análise** com barra de progresso contínua, nome do projeto/perfil ativo, estágio atual do pipeline (Inventário SHA-256 → SAST/Secrets → SonarQube Quality & Hotspots → Grafo Arquitetural → Cadeia de Evidências) e **Tempo Estimado de Conclusão (ETA)** regressivo em segundos.
  3. **Inspeção SonarQube-Grade & Exportação**: Concluída a análise, o usuário inspeciona os cartões de Rating (`A`–`E`), Quality Gate, Security Hotspots e vulnerabilidades CWE/CVSS, podendo exportar o laudo em **JSON**, **SARIF 2.1.0**, **HTML**, **Markdown** ou **CSV**.
- **Visual Identity & Theme**:
  - *Aesthetic Direction*: Console técnico enterprise de alta densidade (SaaS & Developer Dashboard), superfície limpa de nível único com bordas sutis de `1px` (`border-slate-200 dark:border-slate-800`).
  - *Color Palette & Mood*: Neutros frios (`#080b10` / `#0c1017` no modo escuro, `#f8fafc` / `#ffffff` no modo claro) com acento ciano técnico (`#31d6c4`) para progresso ativo e ações primárias, verde esmeralda (`#16a34a`) para Quality Gate aprovado, âmbar (`#d97706`) para alertas e carmesim (`#dc2626`) para bloqueios críticos.
  - *Typography & Hierarchy*: Tipografia sans-serif limpa para navegação e títulos combinada estritamente com fonte monoespaçada e numerais tabulares (`font-mono tabular-nums`) em todos os contadores de progresso, ETAs, percentuais, scores e hashes SHA-256 para evitar qualquer oscilação horizontal durante a contagem regressiva.
- **Interactive Feedback & Motion**:
  - Atualização fluida da barra de progresso global via transições suaves com feedback visual imediato (< 200ms), permitindo que o usuário navegue entre abas enquanto acompanha o progresso e o ETA no topo da tela.

---

## 3. Key Product Decisions & Trade-Offs

- **Decision 1: Execução de Benchmark Assíncrona por Etapas Reais com Telemetria de ETA**
  - *Chosen Approach*: O endpoint de criação de benchmark registra a execução inicialmente com status `RUNNING` e processa as etapas reais de análise atualizando o progresso (`progressPercent`, `currentStageLabel`, `estimatedRemainingSeconds`, `analyzedFilesCount` e `totalFilesCount`). O frontend sincroniza automaticamente enquanto houver execução `RUNNING`.
  - *Why*: Permite que a barra de carregamento global no cabeçalho reflita fielmente cada fase real do motor de análise e calcule o tempo estimado de conclusão com base no volume real de arquivos e linhas de código dos projetos analisados.
  - *Alternatives Considered*: Execução bloqueante síncrona sem estados intermediários (descartada pois impede visibilidade em tempo real da fase ativa e do ETA).

- **Decision 2: Ingestão Real de Arquivos via GitHub REST API (Zero Mock)**
  - *Chosen Approach*: Quando o usuário importa um repositório do GitHub, o backend consulta a árvore/conteúdo real dos arquivos elegíveis do repositório na API pública do GitHub (`api.github.com/repos/:owner/:repo/git/trees` e `raw.githubusercontent.com`), salvando os arquivos reais no diretório isolado e rejeitando a criação de arquivos fictícios quando não há código real.
  - *Why*: Garante que 100% das métricas, achados, linhas de código e hashes SHA-256 pertençam ao código real do repositório escolhido.

- **Decision 3: Motor Estático Expandido Superior ao SonarQube + Exportação SARIF 2.1.0 & HTML**
  - *Chosen Approach*: Expandir o analisador estático nativo para detectar +35 regras reais de engenharia, segurança e qualidade (incluindo detecção de Complexidade Cognitiva elevada por função, Funções Longas, Parâmetros Excessivos, Código Duplicado, Promises sem tratamento, XSS/DOM sinks, Path Traversal, SSRF, Hardcoded Secrets, SQLi, Criptografia Fraca, Ciclos Arquiteturais e Security Hotspots), calculando Ratings `A`–`E` (SQALE/Sonar) e exportando tanto em formatos executivos (`HTML`, `MD`, `CSV`) quanto em formatos de interoperabilidade de ferramentas (`JSON`, `SARIF 2.1.0`).
  - *Why*: Oferece paridade completa com as métricas do SonarQube Community/Server somada à análise de arquitetura hexagonal e trilha de evidências encadeadas por SHA-256.

---

## 4. Technical Architecture & Data Strategy *(Technical Reference)*

### Architecture & Component Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                        Cabeçalho Global da Aplicação                         │
│  ┌────────────────────────┐  ┌────────────────────┐  ┌────────────────────┐  │
│  │ Breadcrumb & Pesquisa  │  │ Botões Upload / GH │  │ Ação de Benchmark  │  │
│  └────────────────────────┘  └────────────────────┘  └────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │        Barra Global "Progresso de Análise" (Quando Status=RUNNING)     │  │
│  │  [Progresso %] [Fase Atual / Adaptador] [Arquivos] [ETA Segundos] [X]  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │ Polling / Sincronização em Tempo Real
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                     Servidor Backend & Orquestrador Real                     │
│                                                                              │
│  ┌──────────────────────────────┐      ┌──────────────────────────────────┐  │
│  │ Ingestão Real (Zero Mock)    │      │ Pipeline Assíncrono de Benchmark │  │
│  │ • Upload Local de Arquivos   │─────▶│ • Fase 1: Inventário & SHA-256   │  │
│  │ • GitHub API Real Tree Fetch │      │ • Fase 2: SAST, Secrets & SCA    │  │
│  └──────────────────────────────┘      │ • Fase 3: SonarQube Quality Gate │  │
│                                        │ • Fase 4: Grafo Arquitetural     │  │
│                                        │ • Fase 5: Cadeia de Evidências   │  │
│                                        └─────────────────┬────────────────┘  │
│                                                          │                   │
│                                                          ▼                   │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │        Motor de Exportação Multi-Formato (/api/reports/:id/export)     │  │
│  │   [JSON Completo]  [SARIF 2.1.0]  [HTML Relatório]  [Markdown]  [CSV]  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Data Model & State
- **Progresso de Execução (`BenchmarkRun.progress`)**:
  - `percent`: Número de `0` a `100` representando o avanço real das etapas.
  - `stageLabel`: Descrição técnica da etapa em execução (ex: `"Analisando Regras SAST, Complexidade Cognitiva e Quality Gate..."`).
  - `estimatedRemainingSeconds`: Tempo estimado restante em segundos calculado dinamicamente a partir da taxa de processamento e volume de arquivos/LOC.
  - `processedFiles` / `totalFiles`: Contagem real de arquivos processados na corrida ativa.
- **Métricas Equivalentes/Superiores ao SonarQube (`SoftwareScoreCard.sonarEquivalentMetrics`)**:
  - `qualityGateStatus`: `'PASSED' | 'WARN' | 'FAILED'`
  - `reliabilityRating`, `securityRating`, `maintainabilityRating`: `'A' | 'B' | 'C' | 'D' | 'E'`
  - `securityHotspotsCount`, `technicalDebtRatioPercent`, `duplicatedBlocksCount`, `highComplexityFunctionsCount`.

### Interactive Component & State Mapping
- **Barra Global `AnalysisProgressHeaderBanner`**:
  - Renderizada automaticamente abaixo da linha principal do `<header>` sempre que houver uma execução com `status === 'RUNNING'` no estado da aplicação.
  - Realiza polling leve (`/api/benchmark-runs/active-progress`) a cada `600ms` enquanto uma corrida estiver em andamento, atualizando a barra de progresso, a etapa atual e o contador regressivo de ETA (`tabular-nums`).
  - Inclui botão funcional de **Interromper Execução** (`/api/benchmark-runs/:id/emergency-stop`) que cancela imediatamente o trabalho em andamento e notifica o usuário.
  - Assim que o status transita para `COMPLETED` ou `COMPLETED_WITH_WARNINGS`, sincroniza o estado global e exibe notificação de conclusão.
- **Módulo de Exportação (`VeracityAdaptersReportsModule`)**:
  - Controles diretos de download para **JSON Completo**, **SARIF 2.1.0 (SonarQube / GitHub Code Scanning)**, **Relatório HTML Interativo**, **Dossiê Markdown** e **Planilha CSV/Excel**, além de visualização de Quality Gate e Ratings A–E.
