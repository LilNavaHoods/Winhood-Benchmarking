# Guia Completo de Utilização — WinHood Software Benchmark & Quality Analyzer

Bem-vindo ao manual oficial do **WinHood Software Benchmark & Quality Analyzer**. Este guia foi elaborado do nível **Básico ao Avançado** com exemplos práticos de comparação **Software A vs. Software B** para garantir total clareza operacional.

---

## 1. Visão Geral & Propósito da Plataforma

O **WinHood Software Benchmark & Quality Analyzer** responde com provas técnicas e matemáticas à pergunta:
> *"Entre o Software A e o Software B, qual possui maior maturidade de segurança, qualidade de código, arquitetura e desempenho — sem depender de opiniões subjetivas ou métricas simuladas?"*

### Princípios Fundamentais
1. **Veracidade Estrita (Zero Dados Fictícios em Estado Vazio)**: Quando nenhuma avaliação foi executada, o sistema inicia limpo (`0` avaliações) e informa seu estado real.
2. **Pontuação Determinística (Escala `0.00` a `5.00`)**: Os mesmos arquivos de código-fonte e os mesmos pesos sempre produzem exatamente a mesma nota.
3. **Travas Matemáticas Eliminatórias (*Kill Switches / Penalty Caps*)**: Vulnerabilidades críticas (como *SQL Injection* ou *Command Injection*) ou segredos hardcoded travam automaticamente a nota máxima do software infrator.
4. **Rastreabilidade Criptográfica (`SHA-256`)**: Todos os pacotes de código, relatórios SARIF 2.1.0, inventários SBOM (`CycloneDX 1.5` / `SPDX 2.3`) e artefatos de evidência possuem assinatura `SHA-256` e `HMAC-SHA256` verificável.

---

## 2. A Jornada de Análise Passo a Passo (6 Etapas Numeradas)

A interface conta com uma **Barra de Jornada Guiada** no topo de todas as telas, dividida em 6 passos sequenciais:

### Passo 1: Cadastrar ou Importar os Softwares A e B (`Projetos & Softwares`)
Você tem 3 maneiras de carregar softwares para comparação:
- **Opção 1 — Carregar Par Real A/B (1 Clique)**: Ingestão imediata dos repositórios reais **VaultCore Internal v2.4.0** (Software A) e **KeeSafe Open v2.56.0** (Software B).
- **Opção 2 — Upload de Código Local**: Clique no botão **Upload** na barra superior para enviar pastas ou arquivos (`.ts`, `.tsx`, `.js`, `.py`, `.sql`, `.json`, `.md`) do seu computador.
- **Opção 3 — Importação de Repositório Git**: Clique no botão de importação na barra superior para pesquisar e importar repositórios públicos diretamente.

### Passo 2: Configurar Pesos Matemáticos, Equivalência e Executar o Benchmark (`Nova Avaliação — Wizard`)
1. Escolha a modalidade: **Avaliação Individual (A)**, **Comparação A/B (B)** ou **Concorrente de Mercado (C)**.
2. Selecione o **Projeto** (opcional) e o **Software Principal** (e concorrentes na Etapa 3 para Comparação A/B).
3. Ajuste o **Perfil de Qualidade Estrita / Modo MQR** e os pesos das **12 Categorias de Avaliação** (*Segurança*, *Qualidade de Código*, *Funcionalidades*, *Arquitetura*, *Desempenho*, *Banco de Dados*, *Confiabilidade*, *Compatibilidade*, *Usabilidade*, *Instalação T0/T1/T2*, *Privacidade* e *Documentação*), garantindo soma exata de **`100%`** (use o botão de normalização automática quando ativar/desativar categorias).
4. Na Etapa 5, revise a pré-análise, configure as **Condições Experimentais & Equivalência do Worker** (vCPUs, RAM, Concorrência VUs, SO Alvo e autorização formal DAST) e clique em **Iniciar Benchmark**.

> **Autenticação Social GitHub:** Quando configurada pelo administrador da instalação, clique diretamente em **Entrar ou cadastrar com GitHub** para autenticar-se pelo navegador via OAuth 2.0 + PKCE (sem necessidade de inserir PAT, senha ou Client ID manualmente). Caso o administrador ainda não tenha habilitado a integração, utilize **Workspace Local (1 clique)**, **Windows Hello / Passkey** ou **Acesso avançado**.

### Passo 3: Qualidade Contínua no Modo MQR, Interoperabilidade SARIF e Remediação Supervisionada (`Ferramentas e Integrações`)
- **Modos de Operação e Interoperabilidade Aberta**:
  - *Motor Autônomo WinHood (AST + Taint + Segredos + IaC + SCA)*
  - *Ingestão de ferramentas que exportam SARIF 2.1.0* com preservação de proveniência (`EXTERNAL_TEST_REPORT_IMPORTED`)
  - *Sincronização autenticada via Bearer Token criptografado em repouso (`AES-256-GCM`)*
- **Comparação Padronizada A/B no Modo MQR**: Executa a análise de Software A e Software B sequencialmente sob o mesmo **Perfil de Qualidade Estrita** e o mesmo Quality Gate, separando indicadores `WINHOOD_NATIVE`, `BENCHMARK_CALCULATED` e `EXTERNAL_TEST_REPORT_IMPORTED` (SARIF v2.1.0).
- **Remediação Autônoma Supervisionada**: Analisa apontamentos e falhas de CI propondo correções determinísticas em **branch isolada (`winhood/remediation-isolated/*`)** com exigência de **aprovação humana obrigatória**, preservando 100% dos arquivos originais.
- **Suíte de 27 Testes de Contrato e Integração**: Valida 15 etapas principais do pipeline + 12 cenários negativos de injeção de falhas.

### Passo 4: Auditar Segurança, Qualidade e Arquitetura
- **Suíte de Segurança & Resiliência**: 15 módulos analíticos, mapeamento de **Superfície de Ataque** e **Cadeias de Ataque (Attack Paths)** classificadas em 6 estados (`CONFIRMADA`, `PROVAVEL`, `FALSO_POSITIVO`, `NAO_REPRODUZIVEL`, `INCONCLUSIVA`, `NAO_TESTADA`).
- **Qualidade & DevSecOps (Modo MQR)**: Inspeção linha a linha de achados SAST, Segredos (com mascaramento automático `VC_***`), SCA e SQL, mapeados para `CWE`, `OWASP Top 10` e `CVSS`.
- **Arquitetura, QA & Perf**: Grafo de acoplamento entre módulos, ciclos arquiteturais, violações de camada, complexidade ciclomática e latência P95.

### Passo 5: Validar Veracidade & Evidências (`Veracidade & Adaptadores`)
- Confirme o estado `SUCCESS_VALIDATED`, audite a confiança da evidência (`HIGH`, `MEDIUM`, `LOW`) e verifique a cadeia de hashes `SHA-256` e assinatura `HMAC-SHA256`.

### Passo 6: Emitir Relatório & Decisão Executiva A/B (`Relatórios & Auditoria`)
- Exporte o laudo técnico consolidado e assinado nos formatos **PDF (`%PDF-1.4`)**, **HTML autocontido**, **SARIF 2.1.0**, **JSON**, **CSV** ou **Markdown (`.md`)**.

---

## 3. Estudo de Caso Prático A/B: VaultCore Internal vs. KeeSafe Open

| Indicador Técnico | Software A: VaultCore Internal v2.4.0 | Software B: KeeSafe Open v2.56.0 | Veredito Técnico |
| :--- | :--- | :--- | :--- |
| **Vulnerabilidades Críticas (SAST)** | SQL Injection (`vaultRepository.ts`), RCE (`execSync` em `cloudBackup.ts`), MD5 + AES-128-ECB + `Math.random()` | `0` vulnerabilidades críticas; usa `AES-256-GCM` e `PBKDF2-SHA512` (600k iterações) | **KeeSafe Open** vence |
| **Segredos Expostos (Secrets)** | Chave mestra hardcoded (`VC_***`) detectada e mascarada | `0` segredos expostos | Aciona **Kill Switch** no VaultCore |
| **Arquitetura & Ciclos** | Dependência circular + Violação de camada (UI acessando SQL direto) | Camadas desacopladas, `0` ciclos, trilha de auditoria íntegra | **KeeSafe Open** vence |
| **Quality Gate (Modo MQR)** | `BLOCKED` (Reprovado — Security Rating E) | `APPROVED` (Aprovado — Ratings A em Segurança, Confiabilidade e Manutenibilidade) | **KeeSafe Open** vence |
| **Nota Composta Final (0.00–5.00)** | **≤ 2.20 / 5.00** (Travado por Kill Switch) | **> 4.50 / 5.00** (**Vencedor Técnico Validado**) | Adoção recomendada: **KeeSafe Open** |

---

## 4. Solução de Problemas Comuns (Wizard, Benchmark A/B e Login GitHub)

### Nova Avaliação (Wizard) e Benchmark A/B
- **Soma de pesos diferente de `100%`:** ao habilitar ou desabilitar categorias na Etapa de Pesos, clique em **Normalizar para 100%** para redistribuir automaticamente os percentuais apenas entre as categorias ativas.
- **Botão de execução bloqueado em Comparação A/B:** confirme que o **Software Principal (A)** e ao menos um **Software Concorrente (B)** distintos estão selecionados e possuem arquivos ingeridos em **Projetos & Softwares**.
- **Comparabilidade marcada como assimétrica / vencedor bloqueado:** verifique na Etapa de Equivalência se ambos os softwares possuem escopo/linguagens compatíveis e condições experimentais alinhadas; quando há assimetria crítica, o motor bloqueia a declaração automática de vencedor por segurança metodológica.
- **Cancelar uma execução em andamento:** utilize o botão de parada de emergência durante a execução para solicitar cancelamento seguro no backend (`POST /api/benchmark-runs/:id/cancel`).

### Login Social GitHub (OAuth 2.0)
- **Botão "Entrar ou cadastrar com GitHub" informa que não está configurado:** o administrador da instância ainda precisa cadastrar o **GitHub OAuth App** no servidor (consulte a Seção 4 do `README.md`). Enquanto isso, você pode usar **Workspace Local (1 clique)** ou **Windows Hello / Passkey**.
- **Erro `redirect_uri_mismatch` na página do GitHub:** a *Authorization callback URL* cadastrada no GitHub Developer Settings diverge da URL configurada no servidor (`http://localhost:3000/api/auth/github/oauth/callback` em dev local ou `https://<dominio>/api/auth/github/oauth/callback` em produção).
- **Erro de sessão/estado expirado ou inválido ao retornar do GitHub:** clique novamente em **Entrar ou cadastrar com GitHub** para iniciar um novo fluxo (cada `state` e `code` OAuth é de uso único por segurança contra replay). Certifique-se de que cookies estão habilitados para o domínio da aplicação.
- **Cadastro via GitHub bloqueado (`signup_disabled`):** o administrador ativou `WINHOOD_GITHUB_ALLOW_SIGNUP=false`; solicite a vinculação prévia da sua conta ou acesse por outro método autorizado.

