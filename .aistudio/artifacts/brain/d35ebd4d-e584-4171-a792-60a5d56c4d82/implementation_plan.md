# Backend Automático & Docker Transparente de 1 Clique

Plano arquitetural para tornar todo o backend e a execução do Docker 100% automatizados e transparentes, para que o usuário não precise abrir terminais, digitar comandos nem conhecer Docker, contando com inicialização automática em 1 clique e fallback fluido para o motor nativo.

---

## User Review & Critical Decisions

> [!IMPORTANT]
> Decisões confirmadas pelo usuário na Fase 1 para automação total:

- **Gerenciamento do Docker**: O backend gerencia o ciclo de vida do container oficial do SonarQube diretamente através de uma API interna (`POST /api/sonar/docker-auto-start`). O usuário conta com um botão simples de **"Iniciar Servidor SonarQube Automaticamente"** (ou disparo automático) sem nunca abrir um terminal.
- **Fallback Inteligente Sem Bloqueio**: Se o Docker Desktop não estiver instalado ou não estiver rodando na máquina, a aplicação **não trava nem exibe erros impeditivos**. Ela aciona automaticamente o **Motor Nativo WinHood de Alta Performance** (equivalente e superior ao SonarQube, com Ratings A–E, SQALE Debt e SARIF 2.1.0) e exibe apenas um aviso sutil e informativo.
- **Fluxo de Análise Zero-Configuração**: Botão de **"Análise Rápida em 1 Clique"** direto na interface. O usuário apenas seleciona ou faz upload do código e clica em analisar: o sistema provisiona o projeto, aloca os núcleos de CPU ideais, executa a varredura, computa o Quality Gate e gera o laudo instantaneamente.

---

## 1. Overview & Core Concept

- **O que faz**: Transforma a interação com ferramentas externas e servidores em uma experiência puramente gráfica de 1 clique:
  1. O backend executa comandos do Docker internamente via chamadas de sistema controladas (`docker run` ou `docker start`), verificando se a porta 9000 já está ativa.
  2. Provisiona automaticamente tokens e projetos sem que o usuário precise navegar em painéis de configuração.
  3. Se o Docker não estiver presente na máquina, ativa o motor nativo local multithread instantaneamente, garantindo 100% de disponibilidade.
- **Público-Alvo**: Desenvolvedores e gestores que desejam a precisão do SonarQube e auditoria de segurança sem a complexidade de configurar containers, portas ou arquivos de configuração no terminal.
- **Valor Principal**: Eliminação de barreiras técnicas. O usuário final precisa apenas usar a aplicação web ou desktop; todo o gerenciamento de infraestrutura, portas e containers é tratado de forma autônoma pelo backend.

---

## 2. User Experience & Visual Design

### A. Fluxos do Usuário

1. **Card de Automação Docker no Sonar Hub**:
   - Um cartão inteligente com status em tempo real:
     - Se o SonarQube já estiver ativo: Exibe status **"Servidor SonarQube Ativo e Pronto"** (ícone verde).
     - Se o SonarQube estiver inativo: Exibe botão principal **"Iniciar SonarQube Automaticamente (1 Clique)"**. Ao clicar, o backend executa a inicialização do container em background com animação de carregamento e feedback de progresso sem que o usuário digite nada.
     - Se o Docker não estiver instalado na máquina: Exibe badge sutil **"Modo Nativo Ultra-Rápido Ativo"** com explicação clara de que todas as notas, Quality Gate e métricas SonarQube são geradas pelo motor interno com zero dependências externas.

2. **Fluxo de Análise Zero-Configuração**:
   - Na barra superior ou no Dashboard, um botão destacado **"Executar Análise Rápida (1 Clique)"**.
   - O modal ou tela resume em uma única etapa: seleciona o projeto e dispara a varredura completa.
   - O backend escolhe automaticamente o melhor motor disponível (Docker SonarQube se online, ou Motor Nativo de alta densidade se offline) e atualiza a barra global de progresso no cabeçalho com ETA regressivo.

### B. Identidade Visual (frontend-design)

- **Simplicidade Operacional**: Eliminação de campos técnicos dispensáveis (URLs de host, flags `-Dsonar...` visíveis apenas em modo avançado opcional).
- **Feedback Transparente**: Indicadores com linguagem direta ao usuário (`"Inicializando container em segundo plano..."`, `"Servidor pronto na porta 9000"`, `"Análise concluída com sucesso"`).
- **Sem Modais Bloqueantes**: Todo o processo ocorre em segundo plano com transição de estados sem recarregar a página.

---

## 3. Key Product Decisions & Trade-Offs

### Decisão 1: Execução do Docker pelo Processo Backend do Node.js
- **Abordagem Escolhida**: Criar endpoint `POST /api/sonar/docker-auto-start` e `POST /api/sonar/docker-stop` no `server.ts` que utiliza `child_process.exec` com timeout seguro e validação de comandos para gerenciar o container `sonarqube:latest`.
- **Por que**: Remove a necessidade de o usuário copiar e colar comandos no PowerShell ou bash.
- **Alternativa Considerada**: Deixar apenas comandos de texto para o usuário rodar no terminal. Descartada para atender à solicitação de automação total.

### Decisão 2: Fallback Transparente para Motor Nativo
- **Abordagem Escolhida**: Se a chamada ao Docker falhar ou o Docker não estiver instalado, a análise continua normalmente usando o analisador estático nativo WinHood, computando Quality Gate (`PASSED`/`FAILED`), Ratings `A`–`E`, complexidade ciclomática e vulnerabilidades CWE/CVSS com emissão de SARIF 2.1.0 e HTML.
- **Por que**: Garante que o usuário consiga analisar seus sistemas imediatamente sem depender de pré-requisitos de software na máquina física.

---

## 4. Technical Architecture & Data Strategy

```
┌────────────────────────────────────────────────────────────────────────┐
│                   FLUXO AUTOMÁTICO ZERO-CONFIGURAÇÃO                   │
├────────────────────────────────────────────────────────────────────────┤
│                           USUÁRIO / FRONTEND                           │
│     ┌────────────────────────────────────────────────────────────┐     │
│     │   Botão "Iniciar Análise em 1 Clique" ou "Iniciar Docker"   │     │
│     └─────────────────────────────┬──────────────────────────────┘     │
│                                   │ POST /api/sonar/docker-auto-start  │
│                                   │ ou POST /api/benchmark-runs/quick  │
│                                   ▼                                    │
├────────────────────────────────────────────────────────────────────────┤
│                        WINHOOD BACKEND ENGINE                          │
│                                                                        │
│               ┌──────────────────────────────────────┐                 │
│               │   Verificador de Ambiente & Docker   │                 │
│               └──────────────────┬───────────────────┘                 │
│                                  │                                     │
│                 ┌────────────────┴────────────────┐                    │
│                 ▼                                 ▼                    │
│     [Docker Instalado / Ativo]        [Docker Ausente / Inativo]       │
│  ┌──────────────────────────────┐   ┌──────────────────────────────┐   │
│  │ child_process: docker start  │   │ Fallback Automático Sutil    │   │
│  │ ou docker run -d ... :9000   │   │ Motor Nativo Multi-Core      │   │
│  │ Aguarda status UP            │   │ (AST + SAST + Sonar Ratings) │   │
│  └──────────────┬───────────────┘   └──────────────┬───────────────┘   │
│                 │                                  │                   │
│                 └────────────────┬─────────────────┘                   │
│                                  ▼                                     │
│                 ┌───────────────────────────────────┐                  │
│                 │ Execução da Avaliação Completa    │                  │
│                 │ Quality Gate + SARIF 2.1.0 + HTML │                  │
│                 └───────────────────────────────────┘                  │
└────────────────────────────────────────────────────────────────────────┘
```

### Componentes e Modificações a Serem Implementados:

1. **Endpoints de Automação Docker em `server.ts`**:
   - `POST /api/sonar/docker-auto-start`:
     - Verifica se o container `sonarqube` já existe (`docker ps -a --filter name=sonarqube`).
     - Se existir e estiver parado, executa `docker start sonarqube`.
     - Se não existir, executa `docker run -d --name sonarqube -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true -p 9000:9000 sonarqube:latest`.
     - Se o Docker daemon não responder ou não estiver instalado, retorna `{ available: false, fallbackToNative: true }`.
   - `POST /api/sonar/docker-stop`:
     - Executa `docker stop sonarqube` de forma segura.
   - `POST /api/benchmark-runs/quick-run`:
     - Executa análise em 1 clique para o projeto selecionado, escolhendo automaticamente o melhor executor disponível sem exigir configuração de formulários.

2. **Aprimoramento do `SonarDockerCloudHubModule.tsx`**:
   - Adicionar o bloco de **Controle Automático do Servidor**:
     - Botão verde/ciano **"Iniciar Servidor SonarQube Automaticamente"** que chama a API e mostra spinner de progresso enquanto sobe o container.
     - Indicador de status claro e sem jargões.
     - Detecção automática de fallback nativo quando Docker não estiver presente na máquina.

3. **Botão de Análise Rápida de 1 Clique no Header / Dashboard**:
   - Permite que qualquer usuário inicie a análise imediatamente a partir da tela principal com zero parâmetros manuais.
