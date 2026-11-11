import {
  BenchmarkCategoryKey,
  BenchmarkProfileConfig,
  ComparabilityReport,
  CriterionEvaluationOutcome,
  DimensionComparabilityEntry,
  DomainSpecializedProfile,
  EvaluationCriterionDefinition,
  NormalizedFinding,
  PreAnalysisSummary,
  Software,
  SourceAvailabilityKind,
  SourceIngestionState,
  ToolAdapterInfo,
} from '../types/benchmark';

export const METHODOLOGY_CATALOG_VERSION = 'WINHOOD-CATALOG-v4.0.0';

export const ALL_12_CATEGORIES: BenchmarkCategoryKey[] = [
  'functionality',
  'code_quality',
  'security',
  'performance',
  'architecture',
  'database',
  'reliability',
  'compatibility',
  'usability',
  'installation',
  'privacy',
  'documentation',
];

export const EVALUATION_CRITERIA_CATALOG: EvaluationCriterionDefinition[] = [
  {
    id: 'CRIT-FUNC-001',
    name: 'Implementação e Cobertura de Fluxos Funcionais Core',
    description: 'Verifica se os módulos principais do domínio declarados possuem implementação real verificável por AST e testes automatizados.',
    domain: 'GENERAL',
    dimension: 'functionality',
    objective: 'Confirmar implementação funcional real além de cascas vazias ou mocks.',
    verificationMethod: 'AST_ANALYSIS',
    requiredTools: ['WinHood Native AST Engine'],
    prerequisites: ['Código-fonte elegível disponível'],
    applicabilityConditions: ['Qualquer software com código-fonte disponível'],
    mandatoryEvidence: ['Módulos exportados', 'Funções de domínio implementadas', 'Arquivos de teste quando existentes'],
    interpretationRule: 'Aprovar apenas quando houver implementação verificável no código-fonte; ausência de erros de sintaxe isoladamente não aprova funcionalidade.',
    severity: 'HIGH',
    weight: 25,
    scoringRule: 'Reduz pontuação proporcionalmente a requisitos não implementados ou não verificados.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Testes funcionais dinâmicos exigem execução de suíte de testes real.'],
  },
  {
    id: 'CRIT-FUNC-002',
    name: 'Validação de Contratos e Tratamento de Entradas Funcionais',
    description: 'Avalia se controladores, serviços ou handlers validam entradas e contratos de domínio.',
    domain: 'GENERAL',
    dimension: 'functionality',
    objective: 'Garantir que entradas inválidas não corrompam fluxos funcionais.',
    verificationMethod: 'STATIC_ANALYSIS',
    requiredTools: ['WinHood Native AST Engine'],
    prerequisites: ['Código-fonte elegível disponível'],
    applicabilityConditions: ['Softwares que processam entrada de usuário, API ou CLI'],
    mandatoryEvidence: ['Schemas de validação, guards de tipo ou verificações explícitas'],
    interpretationRule: 'Requer evidência positiva de validação de parâmetros/contratos.',
    severity: 'MEDIUM',
    weight: 15,
    scoringRule: 'Penaliza ausência de validação em pontos de entrada públicos.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Validações delegadas a gateways externos não são visíveis no código local.'],
  },
  {
    id: 'CRIT-FUNC-KDBX-003',
    name: 'Derivação Criptográfica Argon2id/PBKDF2 e Cofre KDBX 4.x',
    description: 'Verifica implementação de derivação de chave resistente a GPU e parser autenticado de cofre de senhas/segredos.',
    domain: 'PASSWORD_MANAGER',
    dimension: 'functionality',
    objective: 'Confirmar conformidade funcional específica para Gerenciadores de Senhas e Cofres de Segredos.',
    verificationMethod: 'AST_ANALYSIS',
    requiredTools: ['WinHood Native AST Engine'],
    prerequisites: ['Domínio Gerenciador de Senhas ou Cofre de Segredos'],
    applicabilityConditions: ['Somente aplicável a PASSWORD_MANAGER e SECRETS_VAULT'],
    mandatoryEvidence: ['Referências explícitas a Argon2id/PBKDF2/scrypt e cifragem autenticada AES-GCM/ChaCha20-Poly1305'],
    interpretationRule: 'Não aplicável (NOT_APPLICABLE) para softwares fora do domínio de cofre/senhas.',
    severity: 'CRITICAL',
    weight: 30,
    scoringRule: 'Obrigatório para cofres de senhas; isento (NOT_APPLICABLE) para demais domínios.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Análise estática inspeciona primitivas invocadas, não entropia de hardware em runtime.'],
  },
  {
    id: 'CRIT-QUAL-001',
    name: 'Complexidade Ciclomática e Cognitiva Controlada',
    description: 'Mede a complexidade ciclomática e cognitiva por função/arquivo em relação ao tamanho do código.',
    domain: 'GENERAL',
    dimension: 'code_quality',
    objective: 'Prevenir funções monolíticas de difícil manutenção e teste.',
    verificationMethod: 'AST_ANALYSIS',
    requiredTools: ['WinHood Native Quality & Complexity Analyzer'],
    prerequisites: ['Código-fonte elegível disponível'],
    applicabilityConditions: ['Qualquer software com código-fonte'],
    mandatoryEvidence: ['Contagem de desvios condicionais, loops e aninhamento por arquivo'],
    interpretationRule: 'Complexidade média <= 15 por arquivo mantém nota máxima; acima aplica dedução graduada.',
    severity: 'MEDIUM',
    weight: 20,
    scoringRule: 'Dedução baseada em limiares auditáveis de complexidade e dívida técnica.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Arquivos gerados automaticamente devem ser filtrados no inventário.'],
  },
  {
    id: 'CRIT-QUAL-002',
    name: 'Controle de Duplicação de Código e Símbolos Órfãos',
    description: 'Audita densidade de blocos duplicados e variáveis/exportações mortas.',
    domain: 'GENERAL',
    dimension: 'code_quality',
    objective: 'Reduzir custo de manutenção e regressões por cópia de código.',
    verificationMethod: 'STATIC_ANALYSIS',
    requiredTools: ['WinHood Native Quality & Complexity Analyzer'],
    prerequisites: ['Código-fonte elegível disponível'],
    applicabilityConditions: ['Qualquer software com código-fonte'],
    mandatoryEvidence: ['Percentual de linhas duplicadas e contagem de dead code'],
    interpretationRule: 'Densidade de duplicação <= 5.0% mantém conformidade Sonar way.',
    severity: 'LOW',
    weight: 15,
    scoringRule: 'Dedução proporcional à densidade de linhas duplicadas.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Boilerplate de DTOs pode gerar similaridade sintática.'],
  },
  {
    id: 'CRIT-SEC-001',
    name: 'Ausência de Execução Remota de Comandos / Code Injection (CWE-78 / CWE-94)',
    description: 'Inspeciona fluxos Source-to-Sink para eval, new Function, child_process.exec/execSync com interpolação não sanitizada.',
    domain: 'GENERAL',
    dimension: 'security',
    objective: 'Impedir execução arbitrária de código ou comandos de sistema operacional.',
    verificationMethod: 'AST_ANALYSIS',
    requiredTools: ['WinHood Native SAST (AST/Pattern)'],
    prerequisites: ['Código-fonte elegível disponível'],
    applicabilityConditions: ['Qualquer software com código-fonte'],
    mandatoryEvidence: ['Grafo de chamadas AST e trechos de código de sinks de execução'],
    interpretationRule: 'Qualquer sink de execução dinâmica com dados externos reprova o critério com severidade BLOCKER/CRITICAL.',
    severity: 'BLOCKER',
    weight: 35,
    scoringRule: 'Aplica dedução severa e aciona Penalty Cap de segurança.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Ofuscação extrema ou binários nativos exigem DAST/engenharia reversa.'],
  },
  {
    id: 'CRIT-SEC-002',
    name: 'Gestão Segura de Segredos e Ausência de Credenciais Hardcoded (CWE-798)',
    description: 'Verifica se chaves privadas, tokens de API ou senhas estão embutidos no código-fonte.',
    domain: 'GENERAL',
    dimension: 'security',
    objective: 'Garantir que segredos residam exclusivamente em cofres ou variáveis de ambiente protegidas.',
    verificationMethod: 'STATIC_ANALYSIS',
    requiredTools: ['WinHood Native Secret Scanner'],
    prerequisites: ['Código-fonte elegível disponível'],
    applicabilityConditions: ['Qualquer software com código-fonte'],
    mandatoryEvidence: ['Varredura de literais de alta entropia e padrões de chaves/tokens'],
    interpretationRule: 'Credenciais reais ou hardcoded em código de produção reprovam o critério.',
    severity: 'CRITICAL',
    weight: 30,
    scoringRule: 'Dedução direta na dimensão security e bloqueio no Quality Gate.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Não audita variáveis injetadas apenas no ambiente de CI/CD externo.'],
  },
  {
    id: 'CRIT-SEC-003',
    name: 'Criptografia Forte e Proteção de Dados em Repouso (CWE-327)',
    description: 'Exige evidência positiva de uso de algoritmos modernos (AES-256-GCM, ChaCha20, SHA-256/512, Argon2id, PBKDF2) e ausência de MD5/SHA1/DES.',
    domain: 'GENERAL',
    dimension: 'security',
    objective: 'Evitar algoritmos criptográficos quebrados e comprovar proteção criptográfica quando aplicável.',
    verificationMethod: 'AST_ANALYSIS',
    requiredTools: ['WinHood Native SAST (AST/Pattern)'],
    prerequisites: ['Código-fonte elegível disponível'],
    applicabilityConditions: ['Softwares que manipulam autenticação, sessões, tokens ou dados sensíveis'],
    mandatoryEvidence: ['Importações e chamadas a primitivas criptográficas padronizadas'],
    interpretationRule: 'Ausência de MD5/SHA1 sem evidência positiva de criptografia forte resulta em INCONCLUSIVE/NOT_VERIFIED para bônus criptográfico, nunca aprovação automática.',
    severity: 'HIGH',
    weight: 20,
    scoringRule: 'Penaliza algoritmos fracos; concede bônus apenas mediante evidência positiva real no código.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Configurações TLS de proxy reverso externo não constam no código da aplicação.'],
  },
  {
    id: 'CRIT-SEC-004',
    name: 'Segurança da Cadeia de Suprimentos de Software (SCA / SBOM CycloneDX)',
    description: 'Audita dependências declaradas em manifestos contra CVEs conhecidas, EPSS e catálogo CISA KEV.',
    domain: 'GENERAL',
    dimension: 'security',
    objective: 'Mitigar riscos de pacotes de terceiros vulneráveis.',
    verificationMethod: 'STATIC_ANALYSIS',
    requiredTools: ['WinHood Native SCA & Manifest Inspector'],
    prerequisites: ['Manifesto de dependências (package.json, requirements.txt, etc.)'],
    applicabilityConditions: ['Qualquer software que utilize bibliotecas externas'],
    mandatoryEvidence: ['Lista de pacotes e correlação de CVEs'],
    interpretationRule: 'CVEs críticas ou presentes no CISA KEV aplicam penalidade severa em segurança.',
    severity: 'HIGH',
    weight: 15,
    scoringRule: 'Dedução por CVE de acordo com severidade CVSS/EPSS.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Dependências transitivas exigem lockfile presente no pacote.'],
  },
  {
    id: 'CRIT-PERF-001',
    name: 'Eficiência Assintótica e Ausência de Bloqueio Síncrono de Event Loop / I/O',
    description: 'Identifica operações síncronas bloqueantes em rotas críticas, loops aninhados O(N^2+) evitáveis e vazamentos de timers/listeners.',
    domain: 'GENERAL',
    dimension: 'performance',
    objective: 'Prevenir degradação de latência P95/P99 e exaustão de CPU/memória.',
    verificationMethod: 'STATIC_ANALYSIS',
    requiredTools: ['WinHood Native Quality & Complexity Analyzer'],
    prerequisites: ['Código-fonte elegível disponível'],
    applicabilityConditions: ['Qualquer software executável'],
    mandatoryEvidence: ['Inspeção estática de chamadas I/O síncronas e telemetria de runtime quando medida'],
    interpretationRule: 'Se não houver benchmark de runtime real medido, a avaliação limita-se a evidências estáticas de I/O e complexidade, registrando limitação explícita.',
    severity: 'MEDIUM',
    weight: 20,
    scoringRule: 'Penaliza bloqueios síncronos; se runtime não foi executado, reduz confiança para MEDIUM/LOW.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Latência P95/P99 real requer execução de carga em ambiente equivalente.'],
  },
  {
    id: 'CRIT-PERF-002',
    name: 'Telemetria de Latência P50/P95/P99 e Consumo de Memória sob Carga Controlada',
    description: 'Avalia medições reais de latência e memória coletadas por worker de carga em ambiente equivalente.',
    domain: 'GENERAL',
    dimension: 'performance',
    objective: 'Verificar cumprimento de SLAs de latência e footprint de recursos.',
    verificationMethod: 'PERFORMANCE_TEST',
    requiredTools: ['k6 & OpenTelemetry Controlled Load Profiler'],
    prerequisites: ['Ambiente de execução equivalente ativo'],
    applicabilityConditions: ['Serviços, APIs e aplicações executáveis'],
    mandatoryEvidence: ['Métricas OTLP medidas em runtime'],
    interpretationRule: 'Marcado como NOT_EXECUTED quando apenas análise estática é realizada.',
    severity: 'MEDIUM',
    weight: 20,
    scoringRule: 'Avaliado exclusivamente com telemetria real; nunca inferido estaticamente.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Não executável em modo puramente estático.'],
  },
  {
    id: 'CRIT-ARCH-001',
    name: 'Acoplamento Modular, Coesão e Ausência de Dependências Circulares',
    description: 'Constrói o grafo de dependências entre módulos e verifica ciclos e violações de camadas.',
    domain: 'GENERAL',
    dimension: 'architecture',
    objective: 'Garantir arquitetura modular, testável e sem ciclos entre camadas.',
    verificationMethod: 'AST_ANALYSIS',
    requiredTools: ['WinHood Native Architecture Graph Analyzer'],
    prerequisites: ['Múltiplos módulos de código-fonte disponíveis'],
    applicabilityConditions: ['Qualquer software com código-fonte estruturado em módulos'],
    mandatoryEvidence: ['Grafo de importações, índices de acoplamento aferente/eferente e lista de ciclos'],
    interpretationRule: 'Ciclos de dependência e violações de camada reduzem a nota com rastreabilidade ao módulo.',
    severity: 'MEDIUM',
    weight: 20,
    scoringRule: 'Dedução por cada ciclo arquitetural ou violação de fronteira de camada.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Injeção de dependência puramente dinâmica por reflexão pode não aparecer em imports estáticos.'],
  },
  {
    id: 'CRIT-ARCH-002',
    name: 'Isolamento de Camadas Clean/Hexagonal (Presentation -> Domain -> Persistence)',
    description: 'Verifica se controladores/UI não acessam diretamente drivers de banco de dados ou infraestrutura.',
    domain: 'GENERAL',
    dimension: 'architecture',
    objective: 'Preservar independência de regras de negócio em relação a detalhes de infraestrutura.',
    verificationMethod: 'AST_ANALYSIS',
    requiredTools: ['WinHood Native Architecture Graph Analyzer'],
    prerequisites: ['Código-fonte estruturado em camadas'],
    applicabilityConditions: ['Sistemas em camadas, APIs e aplicações corporativas'],
    mandatoryEvidence: ['Arestas do grafo arquitetural entre camadas'],
    interpretationRule: 'Importações diretas de apresentação para persistência geram violação de camada.',
    severity: 'MEDIUM',
    weight: 15,
    scoringRule: 'Dedução por violação de fronteira arquitetural.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Scripts utilitários de arquivo único não possuem separação multicamada.'],
  },
  {
    id: 'CRIT-DB-001',
    name: 'Segurança de Queries Parametrizadas e Integridade de Persistência (CWE-89)',
    description: 'Avalia queries SQL/NoSQL, uso de prepared statements/ORM, transações e índices.',
    domain: 'GENERAL',
    dimension: 'database',
    objective: 'Prevenir SQL Injection e corrupção de estado persistente.',
    verificationMethod: 'STATIC_ANALYSIS',
    requiredTools: ['WinHood Native SQL & Schema Auditor'],
    prerequisites: ['Camada de persistência, banco de dados ou armazenamento estruturado presente'],
    applicabilityConditions: ['Softwares que utilizam banco de dados SQL/NoSQL ou persistência estruturada'],
    mandatoryEvidence: ['Queries parametrizadas, schemas/migrations ou adaptadores de persistência'],
    interpretationRule: 'Se o software não possui camada de banco de dados e o domínio não exige persistência relacional/NoSQL, classificar como NOT_APPLICABLE.',
    severity: 'CRITICAL',
    weight: 20,
    scoringRule: 'SQL Injection reprova o critério; ausência de banco em software stateless marca NOT_APPLICABLE.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Performance de plano de execução (EXPLAIN ANALYZE) requer instância de banco ativa.'],
  },
  {
    id: 'CRIT-DB-002',
    name: 'Otimização de Schemas, Índices de Chaves Estrangeiras e Prevenção de SELECT *',
    description: 'Verifica presença de índices em colunas de junção e ausência de projeções irrestritas SELECT *.',
    domain: 'GENERAL',
    dimension: 'database',
    objective: 'Evitar full table scans e vazamento acidental de colunas sensíveis.',
    verificationMethod: 'STATIC_ANALYSIS',
    requiredTools: ['WinHood Native SQL & Schema Auditor'],
    prerequisites: ['Scripts SQL ou schemas ORM presentes'],
    applicabilityConditions: ['Softwares com persistência SQL/relacional'],
    mandatoryEvidence: ['Inspeção de arquivos .sql e repositórios de dados'],
    interpretationRule: 'Não aplicável para ferramentas stateless sem banco de dados.',
    severity: 'MEDIUM',
    weight: 15,
    scoringRule: 'Dedução por ausência de índice ou SELECT * em tabela sensível.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Índices criados manualmente no SGBD fora das migrations não são visíveis.'],
  },
  {
    id: 'CRIT-REL-001',
    name: 'Tratamento Estruturado de Exceções e Recuperação de Falhas',
    description: 'Verifica blocos catch vazios, promises sem tratamento e ausência de fallbacks resilientes.',
    domain: 'GENERAL',
    dimension: 'reliability',
    objective: 'Evitar falhas silenciosas e quedas abruptas em produção.',
    verificationMethod: 'AST_ANALYSIS',
    requiredTools: ['WinHood Native Quality & Complexity Analyzer'],
    prerequisites: ['Código-fonte elegível disponível'],
    applicabilityConditions: ['Qualquer software com código-fonte'],
    mandatoryEvidence: ['Inspeção de blocos try/catch, handlers de erro e testes automatizados'],
    interpretationRule: 'Blocos catch silenciosos ou erros engolidos geram penalidade direta.',
    severity: 'HIGH',
    weight: 20,
    scoringRule: 'Penaliza cada bloco de exceção silenciado ou ausência de verificação de falha.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Testes de caos/resiliência sob falha de rede requerem execução em sandbox.'],
  },
  {
    id: 'CRIT-REL-002',
    name: 'Densidade de Testes Automatizados e Verificação de Regressão',
    description: 'Verifica a existência e abrangência de arquivos de teste unitário e de integração no repositório.',
    domain: 'GENERAL',
    dimension: 'reliability',
    objective: 'Garantir rede de segurança contra regressões funcionais e operacionais.',
    verificationMethod: 'STATIC_ANALYSIS',
    requiredTools: ['WinHood Native Quality & Complexity Analyzer'],
    prerequisites: ['Código-fonte elegível disponível'],
    applicabilityConditions: ['Qualquer software com código-fonte'],
    mandatoryEvidence: ['Arquivos *.test.* / *.spec.* e asserções verificadas'],
    interpretationRule: 'Zero arquivos de teste resulta em 0% de cobertura verificada (nunca fabricada).',
    severity: 'MEDIUM',
    weight: 15,
    scoringRule: 'Ajusta nota de confiabilidade conforme cobertura real de testes.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Cobertura de linha/branch exata requer instrumentação de runtime.'],
  },
  {
    id: 'CRIT-COMP-001',
    name: 'Portabilidade Multiplataforma e Padronização de Dependências',
    description: 'Inspeciona caminhos hardcoded dependentes de SO, manifestos de pacote e motores suportados.',
    domain: 'GENERAL',
    dimension: 'compatibility',
    objective: 'Garantir execução previsível nos sistemas operacionais e runtimes declarados.',
    verificationMethod: 'STATIC_ANALYSIS',
    requiredTools: ['WinHood Native SCA & Manifest Inspector'],
    prerequisites: ['Código-fonte ou manifesto de empacotamento disponível'],
    applicabilityConditions: ['Qualquer software'],
    mandatoryEvidence: ['package.json/manifestos, uso de path.join/resolve e APIs padrão'],
    interpretationRule: 'Caminhos absolutos hardcoded ou APIs obsoletas reduzem a pontuação.',
    severity: 'LOW',
    weight: 10,
    scoringRule: 'Dedução proporcional a incompatibilidades de caminho ou runtime.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Compatibilidade binária de drivers de kernel exige teste em host nativo.'],
  },
  {
    id: 'CRIT-COMP-002',
    name: 'Interoperabilidade de Contratos e Padronização de Formatos de Exportação',
    description: 'Verifica suporte a formatos abertos padronizados (JSON, SARIF, CycloneDX, UTF-8).',
    domain: 'GENERAL',
    dimension: 'compatibility',
    objective: 'Facilitar integração com pipelines e ferramentas externas.',
    verificationMethod: 'STATIC_ANALYSIS',
    requiredTools: ['WinHood Native AST Engine'],
    prerequisites: ['Código-fonte disponível'],
    applicabilityConditions: ['Qualquer software'],
    mandatoryEvidence: ['Serializadores e parsers padronizados'],
    interpretationRule: 'Aderência a padrões abertos preserva pontuação máxima.',
    severity: 'LOW',
    weight: 10,
    scoringRule: 'Dedução em caso de formatos proprietários bloqueantes.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Protocolos binários legados exigem especificação adicional.'],
  },
  {
    id: 'CRIT-USAB-001',
    name: 'Acessibilidade, Semântica de Interface e Feedback de Erros',
    description: 'Verifica atributos de acessibilidade (aria-*, role, labels), mensagens de erro claras e estrutura de componentes ou CLI.',
    domain: 'GENERAL',
    dimension: 'usability',
    objective: 'Assegurar operabilidade humana clara em interfaces gráficas ou CLIs.',
    verificationMethod: 'STATIC_ANALYSIS',
    requiredTools: ['WinHood Native AST Engine'],
    prerequisites: ['Componentes de interface web/desktop ou interface CLI presentes'],
    applicabilityConditions: ['Softwares com UI (Web/Desktop/Mobile) ou CLI interativa'],
    mandatoryEvidence: ['Componentes UI/CLI, atributos semânticos e mensagens de feedback'],
    interpretationRule: 'Para daemons/bibliotecas/CLIs puras sem UI gráfica, pode ser NOT_APPLICABLE conforme perfil de domínio.',
    severity: 'LOW',
    weight: 10,
    scoringRule: 'Avalia presença de semântica acessível e tratamento amigável de estados.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Teste de usabilidade com usuários reais exige avaliação manual complementar.'],
  },
  {
    id: 'CRIT-INST-001',
    name: 'Automação de Build, Empacotamento e Higiene de Instalação',
    description: 'Verifica scripts de build/instalação reprodutíveis e ausência de mutações inseguras no sistema.',
    domain: 'GENERAL',
    dimension: 'installation',
    objective: 'Garantir instalação/deploy limpo, determinístico e auditável.',
    verificationMethod: 'STATIC_ANALYSIS',
    requiredTools: ['WinHood Native SCA & Manifest Inspector'],
    prerequisites: ['Manifestos de build, scripts de instalação ou configuração de container'],
    applicabilityConditions: ['Qualquer software distribuível ou implantável'],
    mandatoryEvidence: ['Scripts de build/start, lockfiles ou manifestos de instalação'],
    interpretationRule: 'Sem execução em Windows Sandbox real, a verificação é classificada como inspeção estática de manifesto (nunca simulada como execução real).',
    severity: 'LOW',
    weight: 10,
    scoringRule: 'Penaliza ausência de scripts reprodutíveis ou comandos de instalação inseguros.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Diff de registro Windows T0/T1/T2 exige host Windows Sandbox ativo.'],
  },
  {
    id: 'CRIT-PRIV-001',
    name: 'Minimização de Dados, Ausência de Vazamento de PII em Logs e Rastreabilidade',
    description: 'Verifica se senhas, tokens, CPF/cartões ou segredos são despejados em console.log/telemetria sem mascaramento.',
    domain: 'GENERAL',
    dimension: 'privacy',
    objective: 'Garantir conformidade com LGPD/GDPR por design no código-fonte.',
    verificationMethod: 'AST_ANALYSIS',
    requiredTools: ['WinHood Native SAST (AST/Pattern)'],
    prerequisites: ['Código-fonte elegível disponível'],
    applicabilityConditions: ['Qualquer software que processe dados de usuários, credenciais ou logs'],
    mandatoryEvidence: ['Inspeção de chamadas de log, serialização e controles de auditoria/redação'],
    interpretationRule: 'Exige ausência de vazamento em logs E evidência positiva de sanitização/auditoria para nota máxima.',
    severity: 'HIGH',
    weight: 15,
    scoringRule: 'Vazamento de segredo/PII em log aplica penalidade severa em privacy e security.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Políticas jurídicas externas de retenção exigem revisão documental.'],
  },
  {
    id: 'CRIT-PRIV-002',
    name: 'Trilha de Auditoria Imutável (Append-Only) e Redação de Segredos',
    description: 'Verifica se operações sensíveis geram registros de auditoria íntegros sem expor dados secretos.',
    domain: 'GENERAL',
    dimension: 'privacy',
    objective: 'Garantir não-repúdio e conformidade LGPD Art. 46.',
    verificationMethod: 'AST_ANALYSIS',
    requiredTools: ['WinHood Native Data Protection & Encryption Scanner'],
    prerequisites: ['Código-fonte disponível'],
    applicabilityConditions: ['Sistemas corporativos, cofres e APIs'],
    mandatoryEvidence: ['Funções de auditoria/redação verificadas no código'],
    interpretationRule: 'Ausência de trilha de auditoria aplica dedução estrutural em privacidade.',
    severity: 'MEDIUM',
    weight: 15,
    scoringRule: 'Concede nota máxima apenas com evidência positiva de redação e auditoria.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Sistemas de log externos (SIEM) fora do repositório não são inspecionados.'],
  },
  {
    id: 'CRIT-DOC-001',
    name: 'Documentação Técnica, Arquitetural e Guias de Operação',
    description: 'Verifica a existência e densidade de documentação técnica (README, ARCHITECTURE, comentários JSDoc/TSDoc, contratos de API).',
    domain: 'GENERAL',
    dimension: 'documentation',
    objective: 'Permitir auditoria, onboarding e operação segura do software.',
    verificationMethod: 'DOCUMENTATION_REVIEW',
    requiredTools: ['WinHood Native Quality & Complexity Analyzer'],
    prerequisites: ['Repositório ou pacote de código-fonte'],
    applicabilityConditions: ['Qualquer software'],
    mandatoryEvidence: ['Arquivos Markdown (.md), especificações OpenAPI ou comentários de documentação estruturados'],
    interpretationRule: 'Avalia proporção real de artefatos de documentação e comentários técnicos no inventário.',
    severity: 'LOW',
    weight: 10,
    scoringRule: 'Pontuação proporcional à presença verificada de documentação técnica e exemplos.',
    version: '4.0.0',
    maintenanceState: 'ACTIVE',
    knownLimitations: ['Wikis externas fora do repositório só são avaliadas se a URL oficial for fornecida.'],
  },
];

function createWeights(overrides: Partial<Record<BenchmarkCategoryKey, number>>): Record<BenchmarkCategoryKey, number> {
  const base: Record<BenchmarkCategoryKey, number> = {
    functionality: 10,
    code_quality: 10,
    security: 15,
    performance: 10,
    architecture: 10,
    database: 8,
    reliability: 10,
    compatibility: 5,
    usability: 5,
    installation: 5,
    privacy: 7,
    documentation: 5,
  };
  const merged = { ...base, ...overrides };
  const total = Object.values(merged).reduce((acc, v) => acc + v, 0);
  if (total <= 0) return base;
  const normalized = {} as Record<BenchmarkCategoryKey, number>;
  let sum = 0;
  ALL_12_CATEGORIES.forEach((cat, idx) => {
    if (idx === ALL_12_CATEGORIES.length - 1) {
      normalized[cat] = Math.max(0, 100 - sum);
    } else {
      const val = Math.round((merged[cat] / total) * 100);
      normalized[cat] = val;
      sum += val;
    }
  });
  return normalized;
}

// 12 General Dimension Profiles + 15 Domain-Specialized Profiles = 27 Official Profiles
export const DOMAIN_SPECIALIZED_PROFILES: DomainSpecializedProfile[] = [
  // --- 12 GENERAL DIMENSION PROFILES ---
  {
    id: 'general-functionality',
    name: 'Perfil Geral — Funcionalidade e Conformidade de Requisitos',
    domainKey: 'GENERAL_FUNCTIONALITY',
    profileKind: 'GENERAL_DIMENSION',
    description: 'Avaliação transversal com foco prioritário em completude funcional, contratos e fluxos de negócio.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ functionality: 35, reliability: 15, code_quality: 15 }),
    requiredCriteriaIds: ['CRIT-FUNC-001', 'CRIT-FUNC-002', 'CRIT-REL-001'],
    specializedChecks: ['Verificação de exportações de domínio', 'Validação de entradas'],
    targetApplications: ['Qualquer aplicação em validação funcional'],
  },
  {
    id: 'general-code-quality',
    name: 'Perfil Geral — Qualidade de Código e Manutenibilidade (MQR)',
    domainKey: 'GENERAL_CODE_QUALITY',
    profileKind: 'GENERAL_DIMENSION',
    description: 'Foco em Clean Code, baixa complexidade ciclomática/cognitiva, ausência de code smells e dívida técnica.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ code_quality: 35, architecture: 20, documentation: 15 }),
    requiredCriteriaIds: ['CRIT-QUAL-001', 'CRIT-ARCH-001', 'CRIT-DOC-001'],
    specializedChecks: ['Densidade de dívida técnica', 'Complexidade cognitiva por módulo'],
    targetApplications: ['Bibliotecas, SDKs, Monolitos e Sistemas Corporativos'],
  },
  {
    id: 'general-security',
    name: 'Perfil Geral — Segurança AppSec & DevSecOps (OWASP/CWE)',
    domainKey: 'GENERAL_SECURITY',
    profileKind: 'GENERAL_DIMENSION',
    description: 'Auditoria intensiva de vulnerabilidades SAST, Taint Analysis Source-to-Sink, segredos e criptografia.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ security: 40, privacy: 20, reliability: 15 }),
    requiredCriteriaIds: ['CRIT-SEC-001', 'CRIT-SEC-002', 'CRIT-SEC-003', 'CRIT-PRIV-001'],
    specializedChecks: ['Análise Source-to-Sink', 'Detecção de CWE Top 25', 'Varredura de segredos'],
    targetApplications: ['Sistemas críticos e aplicações expostas'],
  },
  {
    id: 'general-performance',
    name: 'Perfil Geral — Desempenho, Eficiência e Escalabilidade',
    domainKey: 'GENERAL_PERFORMANCE',
    profileKind: 'GENERAL_DIMENSION',
    description: 'Foco em eficiência algorítmica, I/O não-bloqueante, uso de memória e latência.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ performance: 35, reliability: 20, architecture: 15 }),
    requiredCriteriaIds: ['CRIT-PERF-001', 'CRIT-REL-001'],
    specializedChecks: ['Detecção de I/O síncrono bloqueante', 'Complexidade de loops'],
    targetApplications: ['Serviços de alto throughput e motores de processamento'],
  },
  {
    id: 'general-architecture',
    name: 'Perfil Geral — Arquitetura, Modularidade e Acoplamento',
    domainKey: 'GENERAL_ARCHITECTURE',
    profileKind: 'GENERAL_DIMENSION',
    description: 'Inspeção de grafos de dependência, acoplamento aferente/eferente, coesão e separação de camadas.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ architecture: 35, code_quality: 25, documentation: 10 }),
    requiredCriteriaIds: ['CRIT-ARCH-001', 'CRIT-QUAL-001'],
    specializedChecks: ['Detecção de ciclos entre módulos', 'Violações de fronteira de camada'],
    targetApplications: ['Sistemas distribuídos, monolitos modulares e plataformas'],
  },
  {
    id: 'general-database',
    name: 'Perfil Geral — Persistência e Segurança de Dados',
    domainKey: 'GENERAL_DATABASE',
    profileKind: 'GENERAL_DIMENSION',
    description: 'Foco em integridade de schemas, queries parametrizadas, prevenção de SQLi e eficiência de acesso a dados.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ database: 35, security: 20, performance: 15 }),
    requiredCriteriaIds: ['CRIT-DB-001', 'CRIT-SEC-001'],
    specializedChecks: ['Inspeção de queries SQL/ORM', 'Prevenção de SQL Injection'],
    targetApplications: ['Sistemas intensivos em dados'],
  },
  {
    id: 'general-reliability',
    name: 'Perfil Geral — Confiabilidade, Resiliência e Tolerância a Falhas',
    domainKey: 'GENERAL_RELIABILITY',
    profileKind: 'GENERAL_DIMENSION',
    description: 'Avalia tratamento de exceções, recuperação de falhas, cobertura de testes e estabilidade operacional.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ reliability: 35, code_quality: 20, security: 15 }),
    requiredCriteriaIds: ['CRIT-REL-001', 'CRIT-FUNC-001'],
    specializedChecks: ['Auditoria de blocos catch vazios', 'Verificação de fluxos de erro'],
    targetApplications: ['Sistemas de missão crítica'],
  },
  {
    id: 'general-compatibility',
    name: 'Perfil Geral — Compatibilidade e Portabilidade Multiplataforma',
    domainKey: 'GENERAL_COMPATIBILITY',
    profileKind: 'GENERAL_DIMENSION',
    description: 'Avalia aderência a padrões multiplataforma, dependências e interoperabilidade de SO/runtime.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ compatibility: 35, installation: 20, architecture: 15 }),
    requiredCriteriaIds: ['CRIT-COMP-001', 'CRIT-INST-001'],
    specializedChecks: ['Verificação de caminhos agnósticos de SO', 'Compatibilidade de motores'],
    targetApplications: ['Aplicações multiplataforma Windows/Linux/macOS'],
  },
  {
    id: 'general-usability',
    name: 'Perfil Geral — Usabilidade, Acessibilidade e Experiência Operacional',
    domainKey: 'GENERAL_USABILITY',
    profileKind: 'GENERAL_DIMENSION',
    description: 'Foco em acessibilidade WCAG/ARIA, clareza de mensagens de erro e ergonomia de interface/CLI.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ usability: 35, functionality: 20, documentation: 15 }),
    requiredCriteriaIds: ['CRIT-USAB-001', 'CRIT-FUNC-001'],
    specializedChecks: ['Inspeção de semântica acessível', 'Feedback estruturado de erro'],
    targetApplications: ['Portais Web, Aplicações Desktop e CLIs interativas'],
  },
  {
    id: 'general-installation',
    name: 'Perfil Geral — Instalação, Empacotamento e Ciclo de Vida',
    domainKey: 'GENERAL_INSTALLATION',
    profileKind: 'GENERAL_DIMENSION',
    description: 'Foco em reprodutibilidade de build, limpeza de artefatos e segurança de scripts de instalação.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ installation: 35, compatibility: 20, security: 15 }),
    requiredCriteriaIds: ['CRIT-INST-001', 'CRIT-COMP-001'],
    specializedChecks: ['Auditoria de scripts postinstall/build', 'Higiene de desinstalação'],
    targetApplications: ['Instaladores Desktop, pacotes CLI e imagens de container'],
  },
  {
    id: 'general-privacy',
    name: 'Perfil Geral — Privacidade e Proteção de Dados (LGPD/GDPR)',
    domainKey: 'GENERAL_PRIVACY',
    profileKind: 'GENERAL_DIMENSION',
    description: 'Auditoria de minimização de dados, redação de logs, proteção de PII e trilhas de auditoria.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ privacy: 35, security: 30, database: 10 }),
    requiredCriteriaIds: ['CRIT-PRIV-001', 'CRIT-SEC-002', 'CRIT-SEC-003'],
    specializedChecks: ['Prevenção de vazamento de PII em logs', 'Criptografia em repouso'],
    targetApplications: ['Sistemas que processam dados pessoais e sensíveis'],
  },
  {
    id: 'general-documentation',
    name: 'Perfil Geral — Documentação Técnica e Auditabilidade',
    domainKey: 'GENERAL_DOCUMENTATION',
    profileKind: 'GENERAL_DIMENSION',
    description: 'Avalia completude de guias de arquitetura, operação, contratos de API e comentários técnicos.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ documentation: 35, architecture: 20, code_quality: 20 }),
    requiredCriteriaIds: ['CRIT-DOC-001', 'CRIT-ARCH-001'],
    specializedChecks: ['Inspeção de README/ARCHITECTURE', 'Densidade de documentação técnica'],
    targetApplications: ['Projetos Open Source, SDKs e plataformas corporativas'],
  },

  // --- 15 DOMAIN-SPECIALIZED PROFILES ---
  {
    id: 'domain-vpn',
    name: 'Domínio Especializado — VPN e Tunelamento Seguro',
    domainKey: 'VPN',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Avaliação especializada para clientes/servidores VPN (WireGuard, OpenVPN, IPsec): foco em criptografia, kill-switch, prevenção de DNS leak, performance de rede e ausência de logs de tráfego.',
    recommendedCategories: ['security', 'privacy', 'performance', 'reliability', 'compatibility', 'installation', 'code_quality', 'architecture', 'functionality', 'documentation'],
    notApplicableCategories: ['database', 'usability'],
    weights: createWeights({ security: 30, privacy: 20, performance: 15, reliability: 12, compatibility: 8, installation: 5, code_quality: 5, architecture: 3, functionality: 2, database: 0, usability: 0, documentation: 0 }),
    requiredCriteriaIds: ['CRIT-SEC-001', 'CRIT-SEC-002', 'CRIT-SEC-003', 'CRIT-PRIV-001', 'CRIT-PERF-001', 'CRIT-REL-001'],
    specializedChecks: ['Política No-Log / Ausência de telemetria de tráfego', 'Criptografia de túnel autenticada', 'Isolamento de privilégios de rede'],
    targetApplications: ['Clientes VPN, Gateways WireGuard/OpenVPN, Proxies de Rede Segura'],
  },
  {
    id: 'domain-password-manager',
    name: 'Domínio Especializado — Gerenciador de Senhas (KDBX / Zero-Knowledge)',
    domainKey: 'PASSWORD_MANAGER',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Perfil rigoroso para cofres de senhas pessoais e corporativos: exige KDF resistente a GPU (Argon2id/PBKDF2), cifragem autenticada (AES-256-GCM/ChaCha20), higienização de memória/clipboard e zero vazamento em logs.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ security: 32, privacy: 18, functionality: 14, reliability: 10, code_quality: 8, database: 5, architecture: 4, usability: 3, performance: 2, compatibility: 2, installation: 1, documentation: 1 }),
    requiredCriteriaIds: ['CRIT-FUNC-KDBX-003', 'CRIT-SEC-001', 'CRIT-SEC-002', 'CRIT-SEC-003', 'CRIT-PRIV-001'],
    specializedChecks: ['Derivação Argon2id/PBKDF2', 'Integridade autenticada de cofre KDBX', 'Zero exposição de senha mestre em logs'],
    targetApplications: ['KeePassXC, Bitwarden, VaultCore, 1Password, Passbolt'],
  },
  {
    id: 'domain-secrets-vault',
    name: 'Domínio Especializado — Cofre de Segredos e KMS Corporativo',
    domainKey: 'SECRETS_VAULT',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Avaliação para cofres de segredos de infraestrutura, rotação de credenciais, envelopes criptográficos, RBAC e trilhas de auditoria imutáveis.',
    recommendedCategories: ['security', 'privacy', 'reliability', 'functionality', 'architecture', 'code_quality', 'performance', 'database', 'documentation', 'compatibility', 'installation'],
    notApplicableCategories: ['usability'],
    weights: createWeights({ security: 35, privacy: 18, reliability: 14, functionality: 10, architecture: 8, code_quality: 6, database: 4, performance: 3, documentation: 2, usability: 0, compatibility: 0, installation: 0 }),
    requiredCriteriaIds: ['CRIT-FUNC-KDBX-003', 'CRIT-SEC-001', 'CRIT-SEC-002', 'CRIT-SEC-003', 'CRIT-PRIV-001', 'CRIT-REL-001'],
    specializedChecks: ['Envelope Encryption / KMS', 'Trilha de auditoria criptográfica', 'Controle de acesso de privilégio mínimo'],
    targetApplications: ['HashiCorp Vault, Infisical, CyberArk, SOPS, Keywhiz'],
  },
  {
    id: 'domain-backup',
    name: 'Domínio Especializado — Sistemas de Backup, Deduplicação e Disaster Recovery',
    domainKey: 'BACKUP',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Foco em integridade de restauração (verificação SHA-256/Merkle), criptografia em repouso/trânsito, resiliência contra interrupções e throughput de I/O.',
    recommendedCategories: ['reliability', 'security', 'performance', 'functionality', 'privacy', 'compatibility', 'installation', 'code_quality', 'architecture', 'documentation'],
    notApplicableCategories: ['usability', 'database'],
    weights: createWeights({ reliability: 30, security: 20, performance: 16, functionality: 12, privacy: 8, compatibility: 5, code_quality: 5, architecture: 2, documentation: 2, usability: 0, database: 0, installation: 0 }),
    requiredCriteriaIds: ['CRIT-REL-001', 'CRIT-SEC-003', 'CRIT-PERF-001', 'CRIT-FUNC-001'],
    specializedChecks: ['Verificação de checksum de blocos', 'Criptografia de snapshots', 'Tolerância a falhas de I/O'],
    targetApplications: ['Restic, BorgBackup, Duplicati, Kopia, Velero'],
  },
  {
    id: 'domain-ticketing-itsm',
    name: 'Domínio Especializado — Gestão de Chamados, Service Desk e ITSM',
    domainKey: 'TICKETING_ITSM',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Avalia fluxos de SLA, filas de atendimento, persistência relacional, controle de acesso multi-tenant, privacidade de anexos/tickets e usabilidade.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ functionality: 22, database: 14, usability: 12, security: 14, privacy: 10, reliability: 10, code_quality: 8, performance: 4, architecture: 4, documentation: 2, compatibility: 0, installation: 0 }),
    requiredCriteriaIds: ['CRIT-FUNC-001', 'CRIT-FUNC-002', 'CRIT-DB-001', 'CRIT-USAB-001', 'CRIT-PRIV-001'],
    specializedChecks: ['Isolamento de tickets por perfil', 'Segurança de queries de busca/filtro', 'Acessibilidade de formulários'],
    targetApplications: ['GLPI, Zammad, osTicket, Redmine, Request Tracker'],
  },
  {
    id: 'domain-crm',
    name: 'Domínio Especializado — CRM (Customer Relationship Management)',
    domainKey: 'CRM',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Foco em proteção de dados pessoais de clientes (LGPD/GDPR), integridade de banco de dados, segurança de APIs, usabilidade e regras de funil de vendas.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ privacy: 20, security: 18, functionality: 18, database: 14, usability: 10, code_quality: 8, reliability: 6, architecture: 4, performance: 2, compatibility: 0, installation: 0, documentation: 0 }),
    requiredCriteriaIds: ['CRIT-PRIV-001', 'CRIT-DB-001', 'CRIT-SEC-001', 'CRIT-FUNC-001', 'CRIT-USAB-001'],
    specializedChecks: ['Conformidade LGPD/PII de contatos', 'Prevenção de SQLi em relatórios', 'Controle de exportação de dados'],
    targetApplications: ['SuiteCRM, EspoCRM, Twenty, Odoo CRM, Krayin'],
  },
  {
    id: 'domain-erp',
    name: 'Domínio Especializado — ERP e Gestão Empresarial Integrada',
    domainKey: 'ERP',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Avalia consistência transacional financeira/estoque, arquitetura modular, banco de dados, auditoria fiscal/operacional e segurança RBAC.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ database: 20, functionality: 18, reliability: 16, security: 16, architecture: 12, code_quality: 8, performance: 5, privacy: 5, usability: 0, compatibility: 0, installation: 0, documentation: 0 }),
    requiredCriteriaIds: ['CRIT-DB-001', 'CRIT-REL-001', 'CRIT-ARCH-001', 'CRIT-SEC-001', 'CRIT-FUNC-001'],
    specializedChecks: ['Integridade transacional ACID', 'Separação modular de domínios', 'Trilha de auditoria financeira'],
    targetApplications: ['ERPNext, Odoo, Dolibarr, iDempiere, Metasfresh'],
  },
  {
    id: 'domain-desktop-app',
    name: 'Domínio Especializado — Aplicações Desktop (Windows / Electron / Tauri / Nativo)',
    domainKey: 'DESKTOP_APP',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Foco em segurança de IPC/empacotamento, higiene de instalação/desinstalação Windows, consumo de memória, responsividade de UI e compatibilidade de SO.',
    recommendedCategories: ['security', 'installation', 'compatibility', 'usability', 'performance', 'reliability', 'functionality', 'code_quality', 'architecture', 'privacy', 'documentation'],
    notApplicableCategories: ['database'],
    weights: createWeights({ security: 20, installation: 15, compatibility: 12, usability: 12, performance: 12, reliability: 10, functionality: 10, code_quality: 5, privacy: 4, database: 0, architecture: 0, documentation: 0 }),
    requiredCriteriaIds: ['CRIT-INST-001', 'CRIT-COMP-001', 'CRIT-USAB-001', 'CRIT-SEC-001', 'CRIT-PERF-001'],
    specializedChecks: ['Isolamento de processo principal/renderer', 'Artefatos residuais de instalação', 'Portabilidade de caminhos de sistema'],
    targetApplications: ['Aplicações Windows, Electron, Tauri, Qt, .NET WPF/WinUI'],
  },
  {
    id: 'domain-web-app',
    name: 'Domínio Especializado — Aplicações Web Modernas (SPA / SSR / Full-Stack)',
    domainKey: 'WEB_APP',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Foco em prevenção de XSS/CSRF/Injection, acessibilidade WCAG, usabilidade, arquitetura de componentes, performance de renderização e privacidade.',
    recommendedCategories: ['security', 'usability', 'functionality', 'code_quality', 'performance', 'architecture', 'privacy', 'reliability', 'compatibility', 'documentation'],
    notApplicableCategories: ['installation', 'database'],
    weights: createWeights({ security: 22, usability: 16, functionality: 16, code_quality: 14, performance: 10, architecture: 10, privacy: 6, reliability: 4, documentation: 2, installation: 0, database: 0, compatibility: 0 }),
    requiredCriteriaIds: ['CRIT-SEC-001', 'CRIT-USAB-001', 'CRIT-FUNC-001', 'CRIT-QUAL-001', 'CRIT-ARCH-001'],
    specializedChecks: ['Prevenção de DOM XSS / dangerouslySetInnerHTML', 'Semântica ARIA e acessibilidade', 'Modularidade de componentes'],
    targetApplications: ['Aplicações React, Next.js, Vue, Angular, Svelte'],
  },
  {
    id: 'domain-api',
    name: 'Domínio Especializado — APIs REST / GraphQL / gRPC e Gateways',
    domainKey: 'API_SERVICE',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Avalia segurança de endpoints (OWASP API Top 10), validação de payloads, latência/throughput, confiabilidade, contratos e persistência; isenta avaliação de interface visual (usability).',
    recommendedCategories: ['security', 'performance', 'reliability', 'functionality', 'architecture', 'code_quality', 'database', 'privacy', 'documentation', 'compatibility'],
    notApplicableCategories: ['usability', 'installation'],
    weights: createWeights({ security: 26, performance: 18, reliability: 16, functionality: 14, code_quality: 10, architecture: 8, database: 4, privacy: 2, documentation: 2, usability: 0, installation: 0, compatibility: 0 }),
    requiredCriteriaIds: ['CRIT-SEC-001', 'CRIT-SEC-002', 'CRIT-FUNC-002', 'CRIT-PERF-001', 'CRIT-REL-001'],
    specializedChecks: ['Validação estrita de schema de entrada', 'Autenticação/Autorização por rota', 'Ausência de bloqueio de Event Loop'],
    targetApplications: ['Backends Node.js/Express/Fastify, Go, Python FastAPI, Spring Boot, .NET Web API'],
  },
  {
    id: 'domain-microservices',
    name: 'Domínio Especializado — Microsserviços e Sistemas Distribuídos',
    domainKey: 'MICROSERVICES',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Foco em desacoplamento arquitetural, tolerância a falhas, observabilidade, contratos assíncronos, performance e segurança entre serviços.',
    recommendedCategories: ['architecture', 'reliability', 'performance', 'security', 'code_quality', 'functionality', 'database', 'documentation', 'compatibility', 'installation'],
    notApplicableCategories: ['usability', 'privacy'],
    weights: createWeights({ architecture: 24, reliability: 20, performance: 16, security: 16, code_quality: 10, functionality: 8, database: 4, documentation: 2, usability: 0, privacy: 0, compatibility: 0, installation: 0 }),
    requiredCriteriaIds: ['CRIT-ARCH-001', 'CRIT-REL-001', 'CRIT-PERF-001', 'CRIT-SEC-001'],
    specializedChecks: ['Baixo acoplamento eferente', 'Resiliência e tratamento de falhas de rede', 'Isolamento de contexto delimitado'],
    targetApplications: ['Malhas de microsserviços, Workers de mensageria, Event-Driven Systems'],
  },
  {
    id: 'domain-database-engine',
    name: 'Domínio Especializado — Motores de Banco de Dados, ORMs e Camadas de Dados',
    domainKey: 'DATABASE_ENGINE',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Avaliação aprofundada de motores de armazenamento, indexação, concorrência, segurança de queries, performance de I/O e confiabilidade.',
    recommendedCategories: ['database', 'performance', 'reliability', 'security', 'architecture', 'code_quality', 'functionality', 'compatibility', 'documentation'],
    notApplicableCategories: ['usability', 'installation', 'privacy'],
    weights: createWeights({ database: 32, performance: 20, reliability: 18, security: 12, architecture: 8, code_quality: 6, functionality: 4, usability: 0, installation: 0, privacy: 0, compatibility: 0, documentation: 0 }),
    requiredCriteriaIds: ['CRIT-DB-001', 'CRIT-PERF-001', 'CRIT-REL-001', 'CRIT-SEC-001'],
    specializedChecks: ['Prevenção de SQL/Query Injection', 'Consistência de transações e locks', 'Eficiência de estruturas de dados'],
    targetApplications: ['Engines SQL/NoSQL, Drivers, Query Builders, ORMs e Camadas de Cache'],
  },
  {
    id: 'domain-monitoring',
    name: 'Domínio Especializado — Sistemas de Monitoramento, Observabilidade e SIEM',
    domainKey: 'MONITORING_OBSERVABILITY',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Avalia coletores de métricas/logs/traces, baixo overhead de CPU/memória, retenção segura, sanitização de dados sensíveis e confiabilidade.',
    recommendedCategories: ['performance', 'reliability', 'security', 'privacy', 'architecture', 'functionality', 'code_quality', 'usability', 'documentation', 'compatibility', 'installation'],
    notApplicableCategories: ['database'],
    weights: createWeights({ performance: 24, reliability: 22, security: 16, privacy: 12, architecture: 10, functionality: 8, code_quality: 6, documentation: 2, database: 0, usability: 0, compatibility: 0, installation: 0 }),
    requiredCriteriaIds: ['CRIT-PERF-001', 'CRIT-REL-001', 'CRIT-PRIV-001', 'CRIT-SEC-001'],
    specializedChecks: ['Sanitização de credenciais em telemetria', 'Baixo overhead de coleta', 'Resiliência de buffer de eventos'],
    targetApplications: ['Prometheus Exporters, Agentes OpenTelemetry, SIEMs, Dashboards de Observabilidade'],
  },
  {
    id: 'domain-devsecops-tool',
    name: 'Domínio Especializado — Ferramentas DevSecOps, SAST, SCA e Auditoria',
    domainKey: 'DEVSECOPS_TOOL',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Perfil calibrado para analisadores estáticos, scanners de segurança, motores de benchmark e ferramentas de CI/CD: exige determinismo, rastreabilidade, precisão e segurança na análise de código não-confiável.',
    recommendedCategories: ALL_12_CATEGORIES,
    notApplicableCategories: [],
    weights: createWeights({ security: 24, code_quality: 18, reliability: 16, functionality: 14, architecture: 10, documentation: 6, performance: 6, privacy: 4, database: 2, usability: 0, compatibility: 0, installation: 0 }),
    requiredCriteriaIds: ['CRIT-SEC-001', 'CRIT-QUAL-001', 'CRIT-REL-001', 'CRIT-ARCH-001', 'CRIT-FUNC-001', 'CRIT-DOC-001'],
    specializedChecks: ['Determinismo de execução', 'Isolamento ao analisar artefatos externos', 'Rastreabilidade SHA-256 de achados'],
    targetApplications: ['Scanners SAST/SCA, Plataformas de Benchmarking, Linters, Orquestradores DevSecOps'],
  },
  {
    id: 'prof-domain-cli-tool',
    name: 'Domínio Especializado — Ferramentas CLI, Infraestrutura (IaC) e Utilitários de Sistema',
    domainKey: 'CLI_TOOL',
    profileKind: 'DOMAIN_SPECIALIZED',
    description: 'Foco em hardening de linha de comando/infraestrutura, execução com privilégio mínimo, reprodutibilidade, segurança de segredos e portabilidade; isenta banco de dados e UI gráfica.',
    recommendedCategories: ['security', 'installation', 'reliability', 'compatibility', 'architecture', 'code_quality', 'performance', 'documentation', 'privacy', 'functionality'],
    notApplicableCategories: ['usability', 'database'],
    weights: createWeights({ security: 28, installation: 20, reliability: 18, compatibility: 12, architecture: 10, code_quality: 6, documentation: 6, usability: 0, database: 0, performance: 0, privacy: 0, functionality: 0 }),
    requiredCriteriaIds: ['CRIT-SEC-001', 'CRIT-SEC-002', 'CRIT-INST-001', 'CRIT-COMP-001', 'CRIT-REL-001'],
    specializedChecks: ['Ausência de credenciais em manifestos', 'Scripts idempotentes e auditáveis', 'Execução sem root desnecessário'],
    targetApplications: ['Ferramentas CLI, Módulos Terraform/Ansible, Dockerfiles, Daemons Linux/Windows'],
  },
].map((p): DomainSpecializedProfile => ({
  ...p,
  profileKind: p.profileKind as 'GENERAL_DIMENSION' | 'DOMAIN_SPECIALIZED',
  profileType: p.profileKind as 'GENERAL_DIMENSION' | 'DOMAIN_SPECIALIZED',
  recommendedCategories: p.recommendedCategories as BenchmarkCategoryKey[],
  enabledCategories: p.recommendedCategories as BenchmarkCategoryKey[],
  notApplicableCategories: p.notApplicableCategories as BenchmarkCategoryKey[],
}));

export function getProfileByIdOrDomain(profileId?: string, domainKey?: string): DomainSpecializedProfile | undefined {
  if (profileId) {
    const byId = DOMAIN_SPECIALIZED_PROFILES.find(
      (p) => p.id === profileId || (profileId === 'domain-infrastructure' && p.id === 'prof-domain-cli-tool')
    );
    if (byId) return byId;
  }
  if (domainKey) {
    const normalized = domainKey.trim().toUpperCase();
    const byDomain = DOMAIN_SPECIALIZED_PROFILES.find(
      (p) =>
        p.domainKey.toUpperCase() === normalized ||
        p.id.toUpperCase() === normalized ||
        (normalized === 'INFRASTRUCTURE' && p.id === 'prof-domain-cli-tool')
    );
    if (byDomain) return byDomain;
  }
  return undefined;
}

export function inferSoftwareDomainKey(software: Software): string {
  if (software.functionalDomain && software.functionalDomain.trim()) {
    const explicit = software.functionalDomain.trim().toUpperCase();
    if (explicit === 'PASSWORD_SECURITY_VAULT') return 'PASSWORD_MANAGER';
    return explicit;
  }
  const tags = [
    ...(software.domainTags || []),
    software.category || '',
    software.name || '',
    software.description || '',
  ]
    .join(' ')
    .toLowerCase();

  if (tags.includes('kdbx') || tags.includes('password') || tags.includes('senha') || tags.includes('keepass') || tags.includes('bitwarden')) {
    return 'PASSWORD_MANAGER';
  }
  if (tags.includes('vault') || tags.includes('secret') || tags.includes('segredo') || tags.includes('kms')) {
    return 'SECRETS_VAULT';
  }
  if (tags.includes('game') || tags.includes('arcade') || tags.includes('engine 2d') || tags.includes('unity')) {
    return 'GAME_INTERACTIVE';
  }
  if (tags.includes('cli') || tags.includes('command line')) {
    return 'CLI_TOOL';
  }
  if (tags.includes('vpn') || tags.includes('wireguard') || tags.includes('openvpn') || tags.includes('tunnel')) {
    return 'VPN';
  }
  if (tags.includes('backup') || tags.includes('restic') || tags.includes('borg') || tags.includes('snapshot')) {
    return 'BACKUP';
  }
  if (tags.includes('ticket') || tags.includes('chamado') || tags.includes('itsm') || tags.includes('helpdesk') || tags.includes('glpi')) {
    return 'TICKETING_ITSM';
  }
  if (tags.includes('crm') || tags.includes('customer relationship')) {
    return 'CRM';
  }
  if (tags.includes('erp') || tags.includes('enterprise resource')) {
    return 'ERP';
  }
  if (tags.includes('sast') || tags.includes('devsecops') || tags.includes('benchmark') || tags.includes('sonar') || tags.includes('scanner')) {
    return 'DEVSECOPS_TOOL';
  }
  if (tags.includes('monitor') || tags.includes('observability') || tags.includes('prometheus') || tags.includes('telemetry')) {
    return 'MONITORING_OBSERVABILITY';
  }
  if (tags.includes('microservice') || tags.includes('microsservi')) {
    return 'MICROSERVICES';
  }
  if (tags.includes('api') || tags.includes('graphql') || tags.includes('rest') || tags.includes('grpc')) {
    return 'API_SERVICE';
  }
  if (tags.includes('desktop') || tags.includes('electron') || tags.includes('tauri') || tags.includes('wpf')) {
    return 'DESKTOP_APP';
  }
  if (tags.includes('database') || tags.includes('postgres') || tags.includes('sqlite') || tags.includes('orm')) {
    return 'DATABASE_ENGINE';
  }
  if (tags.includes('infra') || tags.includes('terraform') || tags.includes('docker') || tags.includes('kubernetes')) {
    return 'CLI_TOOL';
  }
  return 'WEB_APP';
}

export function determineSourceIngestionState(software: Software): SourceIngestionState {
  if (software.ingestionState) {
    return software.ingestionState;
  }
  if (software.dataOrigin === 'DEMO_FIXTURE') return 'DEMO_FIXTURE';
  if (software.dataOrigin === 'TEST_FIXTURE') return 'TEST_FIXTURE';
  if (
    software.sourceType === 'PUBLIC_DOCUMENTATION_ONLY' ||
    software.dataOrigin === 'PUBLIC_DOCUMENTATION_ONLY' ||
    software.dataOrigin === 'OFFICIAL_MARKET_SOURCE'
  ) {
    return 'PUBLIC_DOCUMENTATION_ONLY';
  }
  if (software.sourceType === 'METADATA_ONLY' || software.dataOrigin === 'METADATA_ONLY') {
    return 'METADATA_ONLY';
  }

  const fileEntries = Object.keys(software.sourceFilesContent || {});
  const invEligible = software.inventory?.eligibleFiles ?? fileEntries.length;
  const invVerified = software.inventory?.verifiedIntegrity ?? false;

  if (fileEntries.length === 0 && invEligible === 0) {
    if (software.sourceManifest?.importStatus === 'FAILED') {
      return 'SOURCE_FAILED';
    }
    return 'METADATA_ONLY';
  }

  if (software.sourceManifest?.importStatus === 'PARTIAL' || (software.inventory?.errorFilesCount ?? 0) > 0) {
    return 'SOURCE_PARTIAL';
  }

  if (invVerified && fileEntries.length > 0) {
    return 'SOURCE_VALIDATED';
  }

  return 'SOURCE_IMPORTED';
}

export function determineSourceAvailability(software: Software): SourceAvailabilityKind {
  if (software.sourceAvailability) {
    return software.sourceAvailability;
  }
  const ingestion = determineSourceIngestionState(software);
  if (ingestion === 'PUBLIC_DOCUMENTATION_ONLY') return 'PUBLIC_DOCUMENTATION_ONLY';
  if (ingestion === 'METADATA_ONLY' || ingestion === 'SOURCE_FAILED') return 'CLOSED_SOURCE';
  if (ingestion === 'SOURCE_PARTIAL') return 'PARTIAL_SOURCE';
  return 'FULL_SOURCE';
}

export function evaluateCriteriaForSoftware(params: {
  software: Software;
  findings: NormalizedFinding[];
  enabledCategories: BenchmarkCategoryKey[];
  notApplicableCategories: BenchmarkCategoryKey[];
}): CriterionEvaluationOutcome[] {
  const { software, findings, enabledCategories, notApplicableCategories } = params;
  const outcomes: CriterionEvaluationOutcome[] = [];
  const swDomain = inferSoftwareDomainKey(software);
  const sourceFiles = software.sourceFilesContent || {};
  const filePaths = Object.keys(sourceFiles);
  const allCode = Object.values(sourceFiles).join('\n');
  const ingestionState = determineSourceIngestionState(software);
  const hasRealSource =
    filePaths.length > 0 &&
    ingestionState !== 'METADATA_ONLY' &&
    ingestionState !== 'PUBLIC_DOCUMENTATION_ONLY' &&
    ingestionState !== 'SOURCE_FAILED';

  const activeFindings = findings.filter(
    (f) =>
      f.softwareId === software.id &&
      f.validationStatus !== 'ACCEPTED' &&
      f.validationStatus !== 'ACCEPTED_RISK' &&
      f.validationStatus !== 'FALSE_POSITIVE' &&
      f.validationStatus !== 'FALSE_POSITIVE_REVIEWED' &&
      f.validationStatus !== 'VERIFIED_RESOLVED' &&
      f.validationStatus !== 'NOT_REPRODUCIBLE' &&
      f.validationStatus !== 'INCONCLUSIVE'
  );

  const nowIso = new Date().toISOString();

  for (const crit of EVALUATION_CRITERIA_CATALOG) {
    // Check if dimension is marked NOT_APPLICABLE by profile or domain
    const isDimensionNotApplicable = notApplicableCategories.includes(crit.dimension);
    const isCriterionDomainMismatch =
      crit.domain !== 'GENERAL' &&
      crit.domain !== swDomain &&
      !(crit.domain === 'PASSWORD_MANAGER' && swDomain === 'SECRETS_VAULT');

    // Database special check: if software has no SQL/DB/storage references and domain isn't DB-centric
    const hasDatabaseCode =
      /(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|CREATE\s+TABLE|prisma\.|sequelize|typeorm|knex|mongoose|sqlite|postgres|redis|localStorage|IndexedDB|writeFileSync|readFileSync)/i.test(
        allCode
      );
    const isDbNotApplicable =
      crit.dimension === 'database' &&
      !hasDatabaseCode &&
      !['DATABASE_ENGINE', 'ERP', 'CRM', 'TICKETING_ITSM'].includes(swDomain);

    if (isDimensionNotApplicable || isCriterionDomainMismatch || isDbNotApplicable) {
      outcomes.push({
        criterionId: crit.id,
        criterionName: crit.name,
        dimension: crit.dimension,
        domain: crit.domain,
        verificationMethod: crit.verificationMethod,
        status: 'NOT_APPLICABLE',
        verificationLevel: 'NOT_APPLICABLE',
        scoreImpact: 0,
        evidenceSummary: isCriterionDomainMismatch
          ? `Critério específico do domínio ${crit.domain}; não aplicável ao domínio ${swDomain} deste software.`
          : `Dimensão ${crit.dimension} classificada como NÃO APLICÁVEL para a arquitetura/domínio do software.`,
        evidenceReferences: [],
        limitations: [],
        evaluatedAt: nowIso,
      });
      continue;
    }

    if (!enabledCategories.includes(crit.dimension)) {
      outcomes.push({
        criterionId: crit.id,
        criterionName: crit.name,
        dimension: crit.dimension,
        domain: crit.domain,
        verificationMethod: crit.verificationMethod,
        status: 'NOT_EXECUTED',
        verificationLevel: 'NOT_FOUND',
        scoreImpact: 0,
        evidenceSummary: `Dimensão ${crit.dimension} desabilitada no escopo desta execução.`,
        evidenceReferences: [],
        limitations: ['Dimensão fora do escopo selecionado pelo usuário.'],
        evaluatedAt: nowIso,
      });
      continue;
    }

    if (!hasRealSource) {
      outcomes.push({
        criterionId: crit.id,
        criterionName: crit.name,
        dimension: crit.dimension,
        domain: crit.domain,
        verificationMethod: crit.verificationMethod,
        status: 'NOT_VERIFIED',
        verificationLevel: 'INCONCLUSIVE',
        scoreImpact: 0,
        evidenceSummary: `Código-fonte real não disponível (estado de ingestão: ${ingestionState}). Critério não pôde ser verificado tecnicamente.`,
        evidenceReferences: [],
        limitations: [`Ingestão em estado ${ingestionState} impede verificação estática/AST.`],
        evaluatedAt: nowIso,
      });
      continue;
    }

    // Evaluate specific criteria based on real code evidence and active findings
    const dimFindings = activeFindings.filter((f) =>
      f.mqrImpacts.some((m) => (m.benchmarkCategory || m.category) === crit.dimension)
    );

    if (crit.id === 'CRIT-FUNC-KDBX-003') {
      const hasKdf = /(argon2id|argon2|pbkdf2Sync|scryptSync)/i.test(allCode);
      const hasAead = /(aes-256-gcm|chacha20-poly1305|createCipheriv)/i.test(allCode);
      if (hasKdf && hasAead) {
        outcomes.push({
          criterionId: crit.id,
          criterionName: crit.name,
          dimension: crit.dimension,
          domain: crit.domain,
          verificationMethod: crit.verificationMethod,
          status: 'PASSED_VALIDATED',
          verificationLevel: 'IMPLEMENTATION_FOUND',
          scoreImpact: 0,
          evidenceSummary: 'Primitivas Argon2id/PBKDF2 e cifragem autenticada AES-256-GCM/ChaCha20-Poly1305 identificadas no código-fonte.',
          evidenceReferences: filePaths.slice(0, 3),
          limitations: crit.knownLimitations,
          evaluatedAt: nowIso,
        });
      } else {
        outcomes.push({
          criterionId: crit.id,
          criterionName: crit.name,
          dimension: crit.dimension,
          domain: crit.domain,
          verificationMethod: crit.verificationMethod,
          status: 'FAILED_VALIDATED',
          verificationLevel: 'NOT_FOUND',
          scoreImpact: -1.5,
          evidenceSummary: 'Cofre de senhas/segredos sem evidência completa de derivação KDF forte (Argon2id/PBKDF2) + cifragem autenticada AEAD.',
          evidenceReferences: filePaths.slice(0, 2),
          limitations: crit.knownLimitations,
          evaluatedAt: nowIso,
        });
      }
      continue;
    }

    if (crit.id === 'CRIT-SEC-003') {
      const weakCrypto = activeFindings.filter((f) => f.cwe === 'CWE-327' || /MD5|SHA-?1|DES/i.test(f.title));
      const strongCrypto = /(aes-256-gcm|chacha20-poly1305|argon2id|pbkdf2Sync|scryptSync|crypto\.subtle|createHmac\(\s*['"]sha256['"])/i.test(allCode);
      if (weakCrypto.length > 0) {
        outcomes.push({
          criterionId: crit.id,
          criterionName: crit.name,
          dimension: crit.dimension,
          domain: crit.domain,
          verificationMethod: crit.verificationMethod,
          status: 'FAILED_VALIDATED',
          verificationLevel: 'IMPLEMENTATION_FOUND',
          scoreImpact: -1.2,
          evidenceSummary: `Detectado uso de primitiva criptográfica fraca ou obsoleta (${weakCrypto.map((w) => w.originalRuleId).join(', ')}).`,
          evidenceReferences: weakCrypto.map((w) => `${w.filePath}:${w.lineNumber}`),
          limitations: crit.knownLimitations,
          evaluatedAt: nowIso,
        });
      } else if (strongCrypto) {
        outcomes.push({
          criterionId: crit.id,
          criterionName: crit.name,
          dimension: crit.dimension,
          domain: crit.domain,
          verificationMethod: crit.verificationMethod,
          status: 'PASSED_VALIDATED',
          verificationLevel: 'IMPLEMENTATION_FOUND',
          scoreImpact: 0.15,
          evidenceSummary: 'Primitivas criptográficas fortes (AES-256-GCM / SHA-256 / Argon2id / PBKDF2) verificadas positivamente no código.',
          evidenceReferences: filePaths.slice(0, 3),
          limitations: crit.knownLimitations,
          evaluatedAt: nowIso,
        });
      } else {
        outcomes.push({
          criterionId: crit.id,
          criterionName: crit.name,
          dimension: crit.dimension,
          domain: crit.domain,
          verificationMethod: crit.verificationMethod,
          status: 'INCONCLUSIVE',
          verificationLevel: 'INCONCLUSIVE',
          scoreImpact: 0,
          evidenceSummary: 'Nenhum algoritmo fraco detectado, porém não há evidência positiva de implementação de criptografia em repouso/autenticada nos arquivos analisados.',
          evidenceReferences: [],
          limitations: ['Ausência de padrão vulnerável isoladamente não comprova implementação de proteção criptográfica.'],
          evaluatedAt: nowIso,
        });
      }
      continue;
    }

    if (dimFindings.length > 0) {
      const totalDeduction = dimFindings.reduce((acc, f) => {
        const imp = f.mqrImpacts.find((m) => (m.benchmarkCategory || m.category) === crit.dimension);
        return acc + (imp ? imp.scoreDeduction : -0.25);
      }, 0);
      outcomes.push({
        criterionId: crit.id,
        criterionName: crit.name,
        dimension: crit.dimension,
        domain: crit.domain,
        verificationMethod: crit.verificationMethod,
        status: 'FAILED_VALIDATED',
        verificationLevel: 'IMPLEMENTATION_FOUND',
        scoreImpact: Number(totalDeduction.toFixed(2)),
        evidenceSummary: `${dimFindings.length} apontamento(s) confirmado(s) em ${crit.dimension}: ${dimFindings
          .slice(0, 3)
          .map((f) => `${f.originalRuleId} (${f.filePath}:${f.lineNumber})`)
          .join('; ')}.`,
        evidenceReferences: dimFindings.map((f) => `${f.filePath}:${f.lineNumber}`),
        limitations: crit.knownLimitations,
        evaluatedAt: nowIso,
      });
    } else {
      const hasTests = filePaths.some((p) => /\.(test|spec)\.(ts|tsx|js|jsx|py|go|rs|java|cs)$/i.test(p));
      outcomes.push({
        criterionId: crit.id,
        criterionName: crit.name,
        dimension: crit.dimension,
        domain: crit.domain,
        verificationMethod: crit.verificationMethod,
        status: 'PASSED_VALIDATED',
        verificationLevel: hasTests ? 'VALIDATED_BY_TEST' : 'IMPLEMENTATION_FOUND',
        scoreImpact: 0,
        evidenceSummary: `Inspeção estática/AST concluída em ${filePaths.length} arquivo(s) elegível(is) sem violações para ${crit.id}.`,
        evidenceReferences: filePaths.slice(0, 3),
        limitations: crit.knownLimitations,
        evaluatedAt: nowIso,
      });
    }
  }

  return outcomes;
}

export function evaluateSoftwareComparability(params: {
  softwares: Software[];
  profile?: BenchmarkProfileConfig;
  enabledCategories?: BenchmarkCategoryKey[];
  notApplicableCategories?: BenchmarkCategoryKey[];
  algorithmVersion?: string;
  environmentEquivalent?: boolean;
  criteriaOutcomesBySoftware?: Record<string, CriterionEvaluationOutcome[]>;
}): ComparabilityReport {
  const {
    softwares,
    profile,
    enabledCategories: paramEnabledCategories,
    notApplicableCategories: paramNotApplicableCategories,
    algorithmVersion = 'WINHOOD-SONAR-MQR-v3.0.0',
    environmentEquivalent = true,
    criteriaOutcomesBySoftware = {},
  } = params;

  const blockingReasons: string[] = [];
  const warnings: string[] = [];
  const sourceAvailabilityBySoftware: Record<string, SourceAvailabilityKind> = {};
  const domainsBySoftware: Record<string, string> = {};

  for (const sw of softwares) {
    sourceAvailabilityBySoftware[sw.id] = determineSourceAvailability(sw);
    domainsBySoftware[sw.id] = inferSoftwareDomainKey(sw);
  }

  const distinctDomains = Array.from(new Set(Object.values(domainsBySoftware)));
  const domainCompatible =
    distinctDomains.length <= 1 ||
    distinctDomains.every((d) => ['PASSWORD_MANAGER', 'SECRETS_VAULT', 'PASSWORD_SECURITY_VAULT'].includes(d)) ||
    distinctDomains.every((d) => ['API_SERVICE', 'MICROSERVICES', 'WEB_APP'].includes(d));

  if (!domainCompatible && softwares.length > 1) {
    blockingReasons.push(
      `Domínios funcionais incompatíveis para comparação direta: ${softwares
        .map((s) => `${s.name} (${domainsBySoftware[s.id]})`)
        .join(' vs ')}.`
    );
  }

  const availabilities = Object.values(sourceAvailabilityBySoftware);
  const hasFullSource = availabilities.includes('FULL_SOURCE');
  const hasNonSource = availabilities.some((a) =>
    ['PUBLIC_DOCUMENTATION_ONLY', 'CLOSED_SOURCE', 'MANUAL_ASSESSMENT'].includes(a)
  );
  const sourceAvailabilityCompatible = !(hasFullSource && hasNonSource) && !availabilities.includes('CLOSED_SOURCE');

  if (!sourceAvailabilityCompatible && softwares.length > 1) {
    blockingReasons.push(
      `Assimetria severa de disponibilidade de código-fonte entre os softwares (${softwares
        .map((s) => `${s.name}: ${sourceAvailabilityBySoftware[s.id]}`)
        .join(' vs ')}) impede declaração justa de vencedor oficial.`
    );
  }

  for (const sw of softwares) {
    const ing = determineSourceIngestionState(sw);
    if (ing === 'METADATA_ONLY' || ing === 'SOURCE_FAILED' || ing === 'PUBLIC_DOCUMENTATION_ONLY') {
      blockingReasons.push(
        `Software "${sw.name}" possui estado de ingestão ${ing} (sem código-fonte auditável completo).`
      );
    }
  }

  if (!environmentEquivalent && softwares.length > 1) {
    blockingReasons.push(
      'Ambientes de execução ou limites de recursos não equivalentes entre os softwares avaliados.'
    );
  }

  const enabledCats =
    paramEnabledCategories && paramEnabledCategories.length > 0
      ? paramEnabledCategories
      : profile?.enabledCategories && profile.enabledCategories.length > 0
      ? profile.enabledCategories
      : ALL_12_CATEGORIES;
  const notApplicableCats = paramNotApplicableCategories || profile?.notApplicableCategories || [];

  const dimensionMatrix: DimensionComparabilityEntry[] = ALL_12_CATEGORIES.map((category) => {
    if (notApplicableCats.includes(category)) {
      return {
        category,
        comparable: false,
        status: 'NOT_APPLICABLE',
        coverageBySoftware: Object.fromEntries(softwares.map((s) => [s.id, 0])),
        sourceAvailabilityBySoftware,
        commonCriteriaCount: 0,
        notes: 'Dimensão marcada como NÃO APLICÁVEL pelo perfil de domínio.',
      };
    }

    if (!enabledCats.includes(category)) {
      return {
        category,
        comparable: false,
        status: 'NOT_COMPARABLE',
        coverageBySoftware: Object.fromEntries(softwares.map((s) => [s.id, 0])),
        sourceAvailabilityBySoftware,
        commonCriteriaCount: 0,
        notes: 'Dimensão desabilitada no escopo configurado.',
      };
    }

    const coverageBySoftware: Record<string, number> = {};
    let allHaveFullCoverage = true;
    let anyHasCoverage = false;

    for (const sw of softwares) {
      const avail = sourceAvailabilityBySoftware[sw.id];
      const swOutcomes = (criteriaOutcomesBySoftware[sw.id] || []).filter((o) => o.dimension === category);
      const isSwNotApplicable =
        swOutcomes.length > 0 && swOutcomes.every((o) => o.status === 'NOT_APPLICABLE');

      if (isSwNotApplicable) {
        coverageBySoftware[sw.id] = 0;
        allHaveFullCoverage = false;
      } else if (avail === 'FULL_SOURCE') {
        coverageBySoftware[sw.id] = 100;
        anyHasCoverage = true;
      } else if (avail === 'PARTIAL_SOURCE') {
        coverageBySoftware[sw.id] = 55;
        allHaveFullCoverage = false;
        anyHasCoverage = true;
      } else {
        coverageBySoftware[sw.id] = 0;
        allHaveFullCoverage = false;
      }
    }

    const status: DimensionComparabilityEntry['status'] = allHaveFullCoverage
      ? 'COMPARABLE'
      : anyHasCoverage
      ? 'PARTIALLY_COMPARABLE'
      : 'NOT_COMPARABLE';

    return {
      category,
      comparable: status === 'COMPARABLE',
      status,
      coverageBySoftware,
      sourceAvailabilityBySoftware,
      commonCriteriaCount: EVALUATION_CRITERIA_CATALOG.filter((c) => c.dimension === category).length,
      notes:
        status === 'COMPARABLE'
          ? 'Mesma metodologia, versão de algoritmo e disponibilidade integral de código.'
          : status === 'PARTIALLY_COMPARABLE'
          ? 'Comparabilidade parcial devido a diferença de cobertura ou aplicabilidade entre os alvos.'
          : 'Dimensão não comparável por ausência de artefatos verificáveis.',
    };
  });

  const comparableDimensionsCount = dimensionMatrix.filter((d) => d.comparable).length;
  const scopeCompatible = comparableDimensionsCount > 0;
  if (!scopeCompatible) {
    blockingReasons.push('Nenhuma dimensão possui cobertura equivalente para comparação técnica.');
  }

  const overallComparable =
    domainCompatible &&
    scopeCompatible &&
    environmentEquivalent &&
    sourceAvailabilityCompatible &&
    blockingReasons.length === 0;

  const canDeclareOfficialWinner = softwares.length > 1 && overallComparable;

  if (!canDeclareOfficialWinner && softwares.length > 1 && warnings.length === 0) {
    warnings.push(
      'Declaração de vencedor oficial bloqueada pelo Motor de Imparcialidade: consulte as razões de bloqueio e a matriz de comparabilidade por dimensão.'
    );
  }

  const overallStatus: NonNullable<ComparabilityReport['overallStatus']> = overallComparable
    ? 'COMPARABLE'
    : !domainCompatible
    ? 'NOT_COMPARABLE'
    : !sourceAvailabilityCompatible || blockingReasons.length > 0
    ? 'INCONCLUSIVE_COMPARISON'
    : 'PARTIALLY_COMPARABLE';

  return {
    overallComparable,
    overallStatus,
    canDeclareOfficialWinner,
    domainCompatible,
    objectiveCompatible: true,
    scopeCompatible,
    methodologyCompatible: true,
    environmentCompatible: environmentEquivalent,
    sourceAvailabilityCompatible,
    algorithmVersionMatches: Boolean(algorithmVersion),
    blockingReasons,
    warnings,
    sourceAvailabilityBySoftware,
    dimensionMatrix,
  };
}

export function buildPreAnalysisSummary(
  paramsOrSoftware:
    | {
        software: Software;
        profile?: BenchmarkProfileConfig;
        adapters?: ToolAdapterInfo[];
      }
    | Software,
  enabledCategoriesArg?: BenchmarkCategoryKey[],
  weightsArg?: Record<BenchmarkCategoryKey, number>,
  profileIdArg?: string
): PreAnalysisSummary {
  const isObjectCall =
    typeof paramsOrSoftware === 'object' &&
    paramsOrSoftware !== null &&
    'software' in paramsOrSoftware;

  const software: Software = isObjectCall ? paramsOrSoftware.software : paramsOrSoftware;
  const matchedProfile = getProfileByIdOrDomain(
    isObjectCall ? paramsOrSoftware.profile?.id : profileIdArg,
    software.functionalDomain
  );
  const profile: Partial<BenchmarkProfileConfig> = isObjectCall
    ? paramsOrSoftware.profile || {}
    : {
        id: profileIdArg || matchedProfile?.id || 'custom-profile',
        name: matchedProfile?.name || 'Perfil Customizado',
        enabledCategories: enabledCategoriesArg || matchedProfile?.recommendedCategories || ALL_12_CATEGORIES,
        notApplicableCategories: matchedProfile?.notApplicableCategories || [],
        weights: weightsArg || matchedProfile?.weights,
      };
  const adapters: ToolAdapterInfo[] = isObjectCall ? paramsOrSoftware.adapters || [] : [];

  const ingestionState = determineSourceIngestionState(software);
  const sourceAvailability = determineSourceAvailability(software);
  const inv = software.inventory;
  const sourceFiles = Object.keys(software.sourceFilesContent || {});
  const filesDiscovered = inv?.discoveredFilesCount ?? inv?.totalFiles ?? sourceFiles.length;
  const filesReceived = inv?.receivedFilesCount ?? inv?.totalFiles ?? sourceFiles.length;
  const filesEligible = inv?.eligibleFiles ?? sourceFiles.length;
  const totalLinesOfCode =
    inv?.totalLinesOfCode ??
    Object.values(software.sourceFilesContent || {}).reduce(
      (acc, c) => acc + c.split(/\r?\n/).filter((l) => l.trim().length > 0).length,
      0
    );
  const filesIgnored = inv?.ignoredFilesCount ?? Math.max(0, filesDiscovered - filesEligible);
  const filesUnsupported = inv?.unsupportedFilesCount ?? 0;

  const availableTools =
    adapters.length > 0
      ? adapters
          .filter((a) => a.status === 'OPERATIONAL' || a.status === 'INTEGRAÇÃO CONFIGURADA')
          .map((a) => a.name)
      : [
          'WinHood Native AST Engine',
          'WinHood Native SAST (Taint Mode)',
          'WinHood Native Secret Scanner',
          'WinHood Native Quality & Complexity Analyzer',
          'WinHood Native Architecture Graph Analyzer',
        ];
  const missingTools = adapters
    .filter((a) => a.status === 'FERRAMENTA NÃO INSTALADA' || a.status === 'INTEGRAÇÃO NÃO CONFIGURADA')
    .map((a) => `${a.name} (${a.status})`);

  const enabledCats =
    profile.enabledCategories && profile.enabledCategories.length > 0
      ? profile.enabledCategories
      : ALL_12_CATEGORIES;
  const swDomain = inferSoftwareDomainKey(software);
  const domainProfile = getProfileByIdOrDomain(profile.id, swDomain);
  const notApplicableCats =
    profile.notApplicableCategories && profile.notApplicableCategories.length > 0
      ? profile.notApplicableCategories
      : domainProfile?.notApplicableCategories || [];

  let applicableCriteriaCount = 0;
  let notApplicableCriteriaCount = 0;
  let nonExecutableCriteriaCount = 0;

  for (const crit of EVALUATION_CRITERIA_CATALOG) {
    const isNa =
      notApplicableCats.includes(crit.dimension) ||
      (crit.domain !== 'GENERAL' && crit.domain !== swDomain);
    if (isNa) {
      notApplicableCriteriaCount += 1;
    } else if (!enabledCats.includes(crit.dimension) || filesEligible === 0) {
      nonExecutableCriteriaCount += 1;
    } else {
      applicableCriteriaCount += 1;
    }
  }

  const limitations: string[] = [];
  if (filesEligible === 0) {
    limitations.push(
      `Nenhum arquivo de código-fonte elegível disponível (estado: ${ingestionState}). A avaliação não atribuirá notas numéricas sem evidência.`
    );
  }
  if (missingTools.length > 0) {
    limitations.push(
      `Ferramentas CLI externas não instaladas no host (${missingTools.length}): a análise utilizará exclusivamente o motor AST nativo do WinHood e registrará as ferramentas externas como NOT_INSTALLED.`
    );
  }
  if (!profile.equivalenceEnvironment?.dastFormalAuthorization) {
    limitations.push(
      'Testes intrusivos/DAST desabilitados por ausência de autorização formal do proprietário.'
    );
  }

  const estimatedPotentialCoveragePercent =
    filesEligible === 0
      ? 0
      : sourceAvailability === 'FULL_SOURCE'
      ? Math.round((applicableCriteriaCount / Math.max(1, applicableCriteriaCount + nonExecutableCriteriaCount)) * 100)
      : 50;

  return {
    softwareId: software.id,
    softwareName: software.name,
    softwareVersion: software.version,
    ingestionState,
    sourceAvailability,
    integrityVerified: Boolean((inv?.verifiedIntegrity ?? true) && filesEligible > 0),
    calculatedPackageSha256: software.packageSha256 || 'UNVERIFIED',
    filesDiscovered,
    filesReceived,
    filesEligible,
    eligibleFiles: filesEligible,
    totalFiles: filesReceived,
    totalLinesOfCode,
    filesIgnored,
    filesUnsupported,
    availableTools,
    missingTools,
    applicableCriteriaCount,
    verifiableCriteriaCount: applicableCriteriaCount,
    notApplicableCriteriaCount,
    nonExecutableCriteriaCount,
    notApplicableCategories: notApplicableCats,
    inferredDomain: swDomain,
    recommendedProfileName: domainProfile?.name || profile.name || 'Benchmark Completo Corporativo',
    requiresFormalAuthorization: true,
    limitations,
    warnings: limitations,
    estimatedPotentialCoveragePercent,
  };
}
