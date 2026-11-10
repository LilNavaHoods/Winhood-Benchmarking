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
4. **Rastreabilidade Criptográfica (`SHA-256`)**: Todos os pacotes de código, relatórios do SonarQube e artefatos de evidência possuem assinatura `SHA-256` verificável.

---

## 2. A Jornada de Análise Passo a Passo (6 Etapas Numeradas)

A interface conta com uma **Barra de Jornada Guiada** no topo de todas as telas, dividida em 6 passos sequenciais:

### Passo 1: Cadastrar ou Importar os Softwares A e B (`Projetos & Softwares`)
Você tem 3 maneiras de carregar softwares para comparação:
- **Opção 1 — Carregar Par Real A/B (1 Clique)**: Ingestão imediata dos repositórios reais **VaultCore Internal v2.4.0** (Software A) e **KeeSafe Open v2.56.0** (Software B).
- **Opção 2 — Upload de Código Local**: Clique no botão **Upload** na barra superior para enviar pastas ou arquivos (`.ts`, `.tsx`, `.js`, `.py`, `.sql`, `.json`, `.md`) do seu computador.
- **Opção 3 — Importação do GitHub**: Clique no botão **GitHub** na barra superior para pesquisar e importar repositórios públicos diretamente via API do GitHub.

### Passo 2: Configurar Pesos Matemáticos e Executar o Benchmark (`Wizard de Benchmark`)
1. Selecione o **Projeto** e marque os softwares concorrentes.
2. Ajuste os pesos das **12 Categorias de Avaliação** (*Segurança*, *Qualidade de Código*, *Funcionalidades*, *Arquitetura*, *Desempenho*, *Banco de Dados*, *Confiabilidade*, *Compatibilidade*, *Usabilidade*, *Instalação T0/T1/T2*, *Privacidade* e *Documentação*).
3. Certifique-se de que a **soma matemática seja exatamente `100%`**.
4. Clique em **Executar Benchmark Determinístico Real**.

### Passo 3: Qualidade Contínua com SonarQube, SARIF e Gitar AI (`Ferramentas e Integrações`)
- **3 Modos de Operação SonarQube**:
  - *SonarQube Community Build (Servidor Local)* — `v26.11.0.134175`
  - *SonarQube Servidor Remoto* — Autenticação via cabeçalho HTTP `Authorization: Bearer` com token criptografado em repouso (`AES-256-GCM`)
  - *SonarQube Cloud (`sonarcloud.io`)* — Integração SaaS opcional por `organization` e `projectKey`
- **Comparação Padronizada A/B com SonarQube**: Executa a análise de Software A e Software B sequencialmente na mesma instância, sob o mesmo perfil de qualidade (`Sonar way`) e o mesmo Quality Gate, separando indicadores `SONARQUBE_NATIVE`, `BENCHMARK_CALCULATED` e `EXTERNAL_TEST_REPORT_IMPORTED` (SARIF v2.1.0).
- **Gitar AI (`AI CODE REVIEW & REMEDIATION`)**: Analisa Pull Requests e falhas de CI propondo correções em **branch isolada (`gitar/remediation-isolated/*`)** com exigência de **aprovação humana obrigatória**, preservando 100% dos arquivos originais.
- **Suíte de 27 Testes de Integração**: Valida 15 etapas principais do pipeline + 12 cenários negativos de injeção de falhas.

### Passo 4: Auditar Segurança, Qualidade e Arquitetura
- **Suíte de Segurança & Resiliência**: 15 módulos analíticos, 21 adaptadores de ferramentas, mapeamento de **Superfície de Ataque** e **Cadeias de Ataque (Attack Paths)** classificadas em 6 estados (`CONFIRMADA`, `PROVAVEL`, `FALSO_POSITIVO`, `NAO_REPRODUZIVEL`, `INCONCLUSIVA`, `NAO_TESTADA`).
- **Qualidade & DevSecOps**: Inspeção linha a linha de achados SAST, Segredos (com mascaramento automático `VC_***`), SCA e SQL.
- **Arquitetura, QA & Perf**: Grafo de acoplamento entre módulos, ciclos arquiteturais, violações de camada, complexidade ciclomática e latência P95.

### Passo 5: Validar Veracidade & Evidências (`Veracidade & Adaptadores`)
- Confirme o estado `SUCCESS_VALIDATED`, audite quais ferramentas estão instaladas no sistema operacional e verifique a cadeia de hashes `SHA-256`.

### Passo 6: Emitir Relatório & Decisão Executiva A/B (`Relatórios & Auditoria`)
- Exporte o laudo técnico consolidado nos formatos **JSON**, **Markdown (`.md`)** ou **HTML / PDF para impressão**.

---

## 3. Estudo de Caso Prático A/B: VaultCore Internal vs. KeeSafe Open

| Indicador Técnico | Software A: VaultCore Internal v2.4.0 | Software B: KeeSafe Open v2.56.0 | Veredito Técnico |
| :--- | :--- | :--- | :--- |
| **Vulnerabilidades Críticas (SAST)** | SQL Injection (`vaultRepository.ts`), RCE (`execSync` em `cloudBackup.ts`), MD5 + AES-128-ECB + `Math.random()` | `0` vulnerabilidades críticas; usa `AES-256-GCM` e `PBKDF2-SHA512` (600k iterações) | **KeeSafe Open** vence |
| **Segredos Expostos (Secrets)** | Chave mestra hardcoded (`VC_***`) detectada e mascarada | `0` segredos expostos | Aciona **Kill Switch** no VaultCore |
| **Arquitetura & Ciclos** | Dependência circular + Violação de camada (UI acessando SQL direto) | Camadas desacopladas, `0` ciclos, trilha de auditoria íntegra | **KeeSafe Open** vence |
| **Quality Gate (SonarQube)** | `ERROR` (Reprovado — Security Rating E) | `OK` (Aprovado — Ratings A em Segurança, Confiabilidade e Manutenibilidade) | **KeeSafe Open** vence |
| **Nota Composta Final (0.00–5.00)** | **≤ 2.20 / 5.00** (Travado por Kill Switch) | **> 4.50 / 5.00** (**Vencedor Técnico Validado**) | Adoção recomendada: **KeeSafe Open** |
