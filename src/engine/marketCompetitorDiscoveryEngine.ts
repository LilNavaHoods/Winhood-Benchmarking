/**
 * WinHood Market Competitor Discovery Engine
 *
 * Pesquisa no mercado concorrentes tecnicamente semelhantes a um software informado,
 * utilizando fontes públicas, catálogo de 16 categorias, motor semântico de intenção/ideia,
 * cálculo de similaridade ponderado em 6 eixos e rastreabilidade total (evidências, licenças,
 * código aberto vs proprietário).
 *
 * Regra: Nenhuma funcionalidade ou concorrente inventado.
 */

import type { MarketCompetitorCandidate } from '../types/benchmark';
import { computeSha256 } from './scoringEngine';
import { MARKET_CATEGORIES } from '../shared/benchmarkCategories';

export { MARKET_CATEGORIES };

export interface MarketDiscoveryWeights {
  purpose: number;       // 30%
  features: number;      // 25%
  audience: number;      // 15%
  platform: number;      // 10%
  distribution: number;  // 10%
  integrations: number;  // 10%
}

export const DEFAULT_MARKET_DISCOVERY_WEIGHTS: MarketDiscoveryWeights = {
  purpose: 30,
  features: 25,
  audience: 15,
  platform: 10,
  distribution: 10,
  integrations: 10,
};

export const IDEA_SEMANTIC_CLUSTERS: Record<string, string[]> = {
  ITSM_HELPDESK: [
    'chamado', 'chamados', 'ticket', 'tickets', 'helpdesk', 'service desk', 'itsm',
    'itil', 'suporte', 'atendimento', 'sla', 'incidente', 'incidentes', 'glpi', 'zammad', 'osticket', 'chatwoot', 'jira',
  ],
  WINDOWS_RMM_OPTIMIZER: [
    'windows', 'desktop', 'otimizador', 'limpeza', 'manutencao', 'rmm', 'inventario',
    'ativos', 'hardware', 'endpoint', 'powershell', 'registro', 'servico', 'winutil', 'bleachbit', 'tactical', 'meshcentral', 'fleetdm', 'rustdesk',
  ],
  CODE_QUALITY_BENCHMARK: [
    'qualidade', 'analise estatica', 'sast', 'sca', 'sbom', 'vulnerabilidade', 'benchmark',
    'codigo', 'ast', 'taint', 'seguranca', 'linter', 'auditoria', 'devsecops', 'semgrep', 'codeql', 'trivy', 'snyk',
  ],
  PASSWORD_VAULT_CRYPTO: [
    'senha', 'senhas', 'password', 'vault', 'cofre', 'kdbx', 'criptografia', 'aes',
    'argon2', 'pbkdf2', 'credencial', 'segredo', 'secrets', 'zero-knowledge', 'totp', 'bitwarden', 'keepass', '1password', 'passbolt',
  ],
  MANGA_EBOOK_READER: [
    'manga', 'leitor', 'quadrinho', 'comic', 'cbz', 'cbr', 'epub', 'pdf', 'biblioteca',
    'catalogo', 'capitulo', 'leitura', 'ebook', 'komga', 'kavita', 'mihon', 'tachiyomi', 'calibre', 'sumatrapdf',
  ],
  FITNESS_WORKOUT_TRACKER: [
    'treino', 'academia', 'fitness', 'workout', 'exercicio', 'musculacao', 'saude',
    'caloria', 'serie', 'repeticao', 'ficha', 'nutricao', 'wger', 'fitnotes', 'hevy', 'openscale',
  ],
  NETWORK_MONITORING: [
    'monitoramento', 'rede', 'observabilidade', 'metrica', 'telemetria', 'alerta',
    'ping', 'snmp', 'uptime', 'latencia', 'servidor', 'cpu', 'memoria', 'zabbix', 'prometheus', 'grafana', 'netdata',
  ],
  BACKEND_BAAS_DATABASE: [
    'banco de dados', 'database', 'sql', 'postgres', 'sqlite', 'baas', 'storage',
    'object storage', 's3', 'api', 'backend', 'supabase', 'pocketbase', 'appwrite', 'minio',
  ],
  CYBERSECURITY_SIEM_EDR: [
    'edr', 'siem', 'xdr', 'waf', 'firewall', 'intrusao', 'ips', 'ids', 'dast', 'pentest',
    'scanner', 'wazuh', 'zap', 'nuclei', 'crowdsec', 'vpn', 'wireguard',
  ],
  CLOUD_CONTAINER_GATEWAY: [
    'docker', 'container', 'kubernetes', 'proxy', 'gateway', 'reverse proxy', 'git',
    'ci/cd', 'backup', 'portainer', 'traefik', 'kong', 'gitea',
  ],
};

export interface MarketReferenceDatabaseEntry {
  name: string;
  vendor: string;
  category: string;
  description: string;
  officialUrl: string;
  documentationUrl: string;
  repositoryUrl?: string;
  licenseType: string;
  isOpenSource: boolean;
  sourceAvailability: 'FULL_SOURCE' | 'PARTIAL_SOURCE' | 'CLOSED_SOURCE' | 'PUBLIC_DOCUMENTATION_ONLY';
  features: string[];
  platforms: string[];
  distributionModel: string;
  targetAudience: string[];
  supportedIntegrations: string[];
  primaryPurpose: string;
}

type MarketSoftwareSeed = readonly [
  name: string,
  vendor: string,
  category: string,
  description: string,
  officialUrl: string,
  documentationUrl: string,
  repositoryUrl: string | undefined,
  licenseType: string,
  primaryPurpose: string,
  features: string[],
  platforms: string[],
  distributionModel: string,
  targetAudience: string[],
  supportedIntegrations: string[],
  access?: readonly [isOpenSource: boolean, sourceAvailability: MarketReferenceDatabaseEntry['sourceAvailability']]
];

const buildMarketSoftwareEntry = (seed: MarketSoftwareSeed): MarketReferenceDatabaseEntry => ({
  name: seed[0],
  vendor: seed[1],
  category: seed[2],
  description: seed[3],
  officialUrl: seed[4],
  documentationUrl: seed[5],
  ...(seed[6] ? { repositoryUrl: seed[6] } : {}),
  licenseType: seed[7],
  isOpenSource: seed[14]?.[0] ?? true,
  sourceAvailability: seed[14]?.[1] ?? 'FULL_SOURCE',
  primaryPurpose: seed[8],
  features: seed[9],
  platforms: seed[10],
  distributionModel: seed[11],
  targetAudience: seed[12],
  supportedIntegrations: seed[13],
});

const MARKET_SOFTWARE_SEEDS: readonly MarketSoftwareSeed[] = [
  // 1. Gerenciadores de Senhas & Criptografia
  [
    'Bitwarden', 'Bitwarden Inc.', 'Gerenciadores de Senhas & Criptografia',
    'Cofre de senhas open-source com criptografia de ponta a ponta AES-CBC 256 bits, PBKDF2 SHA-256 e suporte a Argon2id.',
    'https://bitwarden.com', 'https://bitwarden.com/help', 'https://github.com/bitwarden/server', 'GPL-3.0 / AGPL-3.0',
    'Armazenamento seguro, compartilhamento corporativo e sincronização de senhas, cofres zero-knowledge e chaves criptográficas.',
    ['Criptografia ponta-a-ponta AES-256', 'Autenticação 2FA/WebAuthn', 'Compartilhamento em Organização', 'Auditoria de senhas fracas', 'CLI e Extensões de Navegador', 'SSO Corporativo'],
    ['Windows', 'Linux', 'macOS', 'iOS', 'Android', 'Web'], 'Cloud Gerenciado / On-Premise Docker',
    ['Empresas', 'Equipes de TI', 'Usuários Finais', 'Administradores de Segurança'],
    ['Active Directory', 'Okta', 'SAML 2.0', 'SCIM', 'REST API'],
  ],
  [
    'KeePassXC', 'KeePassXC Team', 'Gerenciadores de Senhas & Criptografia',
    'Cofre de senhas open-source local para desktop compatível com formato de banco KDBX 4.1 e derivação Argon2id.',
    'https://keepassxc.org', 'https://keepassxc.org/docs', 'https://github.com/keepassxreboot/keepassxc', 'GPL-2.0 / GPL-3.0',
    'Cofre local de senhas KDBX sem dependência de nuvem com chave mestra, derivação Argon2id e arquivo chave.',
    ['KDBX 4.1 nativo', 'Argon2id e ChaCha20', 'Auto-Type de credenciais', 'Integração com YubiKey/FIDO2', 'Sem telemetria', 'CLI integrada'],
    ['Windows', 'Linux', 'macOS'], 'Binário Executável Local (Desktop)',
    ['Engenheiros de Segurança', 'Administradores de Infraestrutura', 'Usuários Avançados'],
    ['Extensão de Navegador nativa via IPC', 'SSH Agent', 'Freedesktop Secret Service'],
  ],
  [
    '1Password', 'AgileBits Inc.', 'Gerenciadores de Senhas & Criptografia',
    'Solução corporativa e pessoal proprietária de gerenciamento de senhas com Secret Key de 128 bits e cofre AES-GCM-256.',
    'https://1password.com', 'https://support.1password.com', undefined, 'Comercial Proprietária',
    'Gerenciamento centralizado de identidades, credenciais corporativas, cofres zero-knowledge e segredos de infraestrutura (Secrets Automation).',
    ['Secret Key de 128 bits', 'AES-256-GCM', 'Watchtower de vazamentos', 'Secrets Automation para DevOps', 'Auditoria granular de acessos', 'CLI e Extensões Web'],
    ['Windows', 'Linux', 'macOS', 'iOS', 'Android', 'Web'], 'SaaS / Nuvem Comercial',
    ['Empresas Enterprise', 'Equipes de Engenharia', 'DevOps', 'Security Teams'],
    ['Slack', 'Okta', 'Azure AD', 'Kubernetes Operator', 'Terraform Provider'],
    [false, 'CLOSED_SOURCE'],
  ],
  [
    'Vaultwarden', 'Vaultwarden Community', 'Gerenciadores de Senhas & Criptografia',
    'Implementação alternativa leve e open-source em Rust da API do servidor Bitwarden para auto-hospedagem de baixo consumo.',
    'https://github.com/dani-garcia/vaultwarden', 'https://github.com/dani-garcia/vaultwarden/wiki', 'https://github.com/dani-garcia/vaultwarden', 'GPL-3.0',
    'Servidor auto-hospedado leve em Rust para gerenciamento de senhas, TOTP e cofres criptografados.',
    ['API Bitwarden compatível', 'Baixo consumo de RAM em Rust', 'SQLite/PostgreSQL/MySQL', 'WebSocket live sync', 'Suporte a WebAuthn e TOTP'],
    ['Linux', 'Docker', 'Windows'], 'Self-hosted Container / Binário Rust',
    ['Self-hosters', 'Pequenas e Médias Empresas', 'Equipes de DevSecOps'],
    ['Clientes oficiais Bitwarden', 'Reverse Proxies', 'LDAP Sync'],
  ],
  [
    'Passbolt', 'Passbolt SA', 'Gerenciadores de Senhas & Criptografia',
    'Gerenciador de senhas open-source para equipes de engenharia e operações baseado em criptografia OpenPGP.',
    'https://www.passbolt.com', 'https://help.passbolt.com', 'https://github.com/passbolt/passbolt_api', 'AGPL-3.0',
    'Compartilhamento colaborativo de credenciais e senhas em equipes com criptografia GPG/OpenPGP.',
    ['Criptografia OpenPGP no cliente', 'RBAC por pastas e grupos', 'Auditoria de compartilhamento', 'Extensão de navegador verificada', 'MFA TOTP/YubiKey'],
    ['Linux', 'Docker', 'Web', 'iOS', 'Android'], 'On-Premise / Cloud SaaS',
    ['Times de DevOps', 'Agências Digitais', 'Equipes de Segurança'],
    ['LDAP', 'SAML 2.0', 'REST API', 'CLI'],
  ],

  // 2. Software Quality & Análise de Código / DevSecOps
  [
    'Semgrep OSS', 'Semgrep Inc.', 'Software Quality & Análise de Código',
    'Motor estático ultrarrápido baseado em regras AST declarativas para busca de vulnerabilidades, SAST e padrões de código.',
    'https://semgrep.dev', 'https://semgrep.dev/docs/', 'https://github.com/semgrep/semgrep', 'LGPL-2.1',
    'Análise estática de código (SAST), qualidade e auditoria de segurança com regras AST em mais de 30 linguagens.',
    ['Engine AST multi-linguagem', 'Regras YAML customizadas', 'Exportação SARIF 2.1.0', 'Integração CLI e CI/CD', 'Taint Analysis'],
    ['Linux', 'macOS', 'Windows (WSL)', 'Docker'], 'CLI Open-Source / SaaS Opcional',
    ['Equipes de AppSec', 'Engenheiros de Software', 'DevSecOps'],
    ['GitHub Actions', 'GitLab CI', 'Jenkins', 'VS Code'],
  ],
  [
    'MqrBridge Community Build', 'SonarSource', 'Software Quality & Análise de Código',
    'Plataforma open-core de inspeção contínua da qualidade do código com suporte a mais de 30 linguagens e Quality Gates MQR.',
    'https://www.sonarsource.com/products/mqr-bridge/', 'https://docs.sonarsource.com/mqr-bridge-community-build/', 'https://github.com/SonarSource/mqr-bridge', 'LGPL-3.0',
    'Detecção estática de bugs, vulnerabilidades, code smells, dívida técnica e medição de cobertura de testes.',
    ['Quality Gate', 'Análise estática multi-linguagem', 'Detecção de duplicação', 'Gestão de dívida técnica', 'Webhooks CI/CD'],
    ['Linux', 'Windows', 'Docker'], 'On-Premise Server / Docker',
    ['Times de Engenharia', 'Tech Leads', 'Arquitetos de Software'],
    ['GitHub Actions', 'GitLab CI', 'Jenkins', 'Azure DevOps', 'VS Code'],
  ],
  [
    'GitHub CodeQL', 'GitHub / Microsoft', 'DevSecOps & SAST/DAST/SCA',
    'Motor de análise semântica de código que trata código-fonte como banco de dados relacional para descobrir vulnerabilidades complexas e fluxos de taint.',
    'https://codeql.github.com', 'https://codeql.github.com/docs/', 'https://github.com/github/codeql', 'MIT (Queries) / Proprietária (CLI)',
    'Análise profunda de fluxo de dados (Taint Analysis), variante de vulnerabilidades e auditoria SAST.',
    ['Consultas declarativas QL', 'Dataflow e Taint Tracking interprocedural', 'Saída SARIF nativa', 'Suporte a TS/JS, Python, Java, C#, Go, C++'],
    ['Windows', 'Linux', 'macOS'], 'CLI / GitHub Advanced Security',
    ['Pesquisadores de Segurança', 'Equipes de AppSec', 'Desenvolvedores'],
    ['GitHub Actions', 'VS Code CodeQL Extension', 'SARIF Viewers'],
    [true, 'PARTIAL_SOURCE'],
  ],
  [
    'Trivy', 'Aqua Security', 'DevSecOps & SAST/DAST/SCA',
    'Scanner abrangente e open-source de vulnerabilidades SCA, geração de SBOM (CycloneDX/SPDX), segredos e configurações IaC.',
    'https://trivy.dev', 'https://aquasecurity.github.io/trivy/', 'https://github.com/aquasecurity/trivy', 'Apache-2.0',
    'Análise de composição de software (SCA), geração de SBOM, detecção de segredos e auditoria IaC (Dockerfile, Terraform, Kubernetes).',
    ['Scanner SCA multi-ecossistema', 'Geração de SBOM CycloneDX e SPDX', 'Auditoria de Dockerfile e Kubernetes', 'Detecção de segredos', 'Exportação SARIF'],
    ['Linux', 'Windows', 'macOS', 'Docker'], 'Binário CLI / Container',
    ['Engenheiros DevSecOps', 'SREs', 'Equipes de Segurança Cloud'],
    ['GitHub Actions', 'GitLab CI', 'Kubernetes Operator', 'VS Code'],
  ],
  [
    'Snyk CLI', 'Snyk Ltd.', 'DevSecOps & SAST/DAST/SCA',
    'Ferramenta focada no desenvolvedor para detecção e correção de vulnerabilidades em dependências open-source (SCA), código (SAST), containers e IaC.',
    'https://snyk.io', 'https://docs.snyk.io', 'https://github.com/snyk/cli', 'Apache-2.0 (CLI) / SaaS Comercial',
    'Identificação de vulnerabilidades de dependências, SAST em tempo real e automação de Pull Requests de correção.',
    ['Base proprietária de vulnerabilidades', 'Snyk Code SAST', 'Correção automática em PRs', 'Auditoria de licenças', 'Geração de SBOM'],
    ['Windows', 'Linux', 'macOS'], 'CLI + Plataforma SaaS',
    ['Desenvolvedores', 'Equipes de AppSec', 'Gestores de Engenharia'],
    ['GitHub', 'GitLab', 'Jira', 'VS Code', 'JetBrains'],
    [false, 'PARTIAL_SOURCE'],
  ],

  // 3. ITSM & Service Desk (Chamados / Helpdesk)
  [
    'GLPI', 'Teclib', 'ITSM & Service Desk',
    'Solução open-source completa para gerenciamento de serviços de TI (ITSM), abertura de chamados (helpdesk) e inventário automático de ativos.',
    'https://glpi-project.org', 'https://glpi-project.org/documentation/', 'https://github.com/glpi-project/glpi', 'GPL-3.0',
    'Gerenciamento de chamados de suporte (tickets/helpdesk), controle de SLA, ativos de hardware/software e processos ITIL.',
    ['Helpdesk e abertura de chamados multi-entidade', 'Inventário automático de computadores com agente', 'Gestão de mudanças e problemas ITIL', 'Base de conhecimento e FAQ', 'Controle de SLA e escalonamento'],
    ['Linux', 'Windows Server', 'Docker', 'Web'], 'On-Premise / Cloud',
    ['Departamentos de TI', 'Suporte Técnico / Service Desk', 'Gestores de Ativos'],
    ['LDAP / Active Directory', 'OAuth 2.0', 'GLPI Agent', 'REST API'],
  ],
  [
    'Zammad', 'Zammad GmbH', 'ITSM & Service Desk',
    'Sistema web open-source moderno de helpdesk, suporte ao cliente e gestão de chamados com busca full-text e múltiplos canais.',
    'https://zammad.org', 'https://docs.zammad.org', 'https://github.com/zammad/zammad', 'AGPL-3.0',
    'Centralização de chamados de suporte, atendimento multicanal (e-mail, chat, telefone) e automação de filas de tickets.',
    ['Gestão de tickets em tempo real', 'Gatilhos e macros de SLA', 'Base de conhecimento multilíngue', 'Auditoria de histórico de atendimento', 'API REST e Webhooks'],
    ['Linux', 'Docker', 'Web'], 'Self-hosted / SaaS',
    ['Equipes de Suporte', 'Helpdesk de TI', 'Atendimento ao Cliente'],
    ['LDAP', 'SAML', 'Slack', 'GitLab', 'GitHub'],
  ],
  [
    'osTicket', 'Enhancesoft', 'ITSM & Service Desk',
    'Plataforma open-source amplamente adotada para abertura de chamados técnicos, roteamento de tickets e portal de atendimento.',
    'https://osticket.com', 'https://docs.osticket.com', 'https://github.com/osTicket/osTicket', 'GPL-2.0',
    'Sistema leve de abertura de chamados, acompanhamento de solicitações de suporte e controle de SLA.',
    ['Formulários customizados de chamados', 'Filtros automáticos de roteamento', 'Planos de SLA', 'bloqueio de colisão entre agentes', 'Portal web do solicitante'],
    ['Linux', 'Windows', 'Web'], 'On-Premise / Cloud',
    ['Pequenas e Médias Empresas', 'Suporte de TI Interno', 'Universidades'],
    ['Active Directory / LDAP', 'OAuth2', 'E-mail Piping / IMAP'],
  ],
  [
    'Chatwoot', 'Chatwoot Inc.', 'ITSM & Service Desk',
    'Suite open-source de atendimento ao cliente, suporte omnichannel e gestão colaborativa de conversas e tickets.',
    'https://www.chatwoot.com', 'https://www.chatwoot.com/docs', 'https://github.com/chatwoot/chatwoot', 'MIT / Enterprise',
    'Atendimento e suporte técnico unificado com caixa de entrada compartilhada, automação de chamados e relatórios de SLA.',
    ['Inbox compartilhada omnichannel', 'Regras de automação e SLA', 'Centro de ajuda / Help Center', 'Notas privadas e menções da equipe', 'Relatórios de tempo de resolução'],
    ['Linux', 'Docker', 'Web', 'iOS', 'Android'], 'Self-hosted Docker / Cloud',
    ['Suporte ao Cliente', 'Equipes de Produto', 'Service Desk Moderno'],
    ['Slack', 'WhatsApp', 'Telegram', 'E-mail', 'Webhooks'],
  ],
  [
    'Jira Service Management', 'Atlassian', 'ITSM & Service Desk',
    'Plataforma proprietária de gerenciamento de serviços de TI (ITSM) com filas de chamados, gestão de incidentes e portal de autosserviço.',
    'https://www.atlassian.com/software/jira/service-management', 'https://support.atlassian.com/jira-service-management-cloud/', undefined, 'Comercial Proprietária',
    'Central de serviços corporativos e chamados de TI com gestão de incidentes, mudanças, ativos e integrações DevOps.',
    ['Portal de autosserviço de chamados', 'Fluxos ITIL certificados', 'Automação de triagem', 'Gestão de ativos (Assets)', 'Escalonamento de incidentes'],
    ['Cloud SaaS', 'Web', 'Mobile'], 'SaaS Nuvem',
    ['Equipes de Suporte', 'Operações de TI', 'Desenvolvedores'],
    ['Confluence', 'Opsgenie', 'Slack', 'Microsoft Teams', 'GitHub'],
    [false, 'CLOSED_SOURCE'],
  ],

  // 4. Monitoramento & Observabilidade
  [
    'Zabbix', 'Zabbix LLC', 'Monitoramento & Observabilidade',
    'Plataforma corporativa open-source de monitoramento de redes, servidores, agentes Windows/Linux, nuvens e serviços.',
    'https://www.zabbix.com', 'https://www.zabbix.com/documentation/current/', 'https://github.com/zabbix/zabbix', 'AGPL-3.0',
    'Monitoramento de infraestrutura, redes e endpoints em tempo real com coleta por agente ou SNMP/IPMI.',
    ['Coleta multi-protocolo SNMP/Agent', 'Descoberta automática de rede', 'Gatilhos preditivos de alertas', 'Mapas topológicos de rede', 'API JSON-RPC completa'],
    ['Linux', 'Windows (Agente)', 'Docker'], 'On-Premise / Servidor Dedicado',
    ['Equipes de Infraestrutura', 'NOC', 'SysAdmins'],
    ['Grafana', 'Telegram', 'Jira', 'PagerDuty', 'SNMP'],
  ],
  [
    'Prometheus', 'CNCF / Prometheus Authors', 'Monitoramento & Observabilidade',
    'Sistema open-source de monitoramento e banco de dados de séries temporais (TSDB) com linguagem de consulta PromQL e Alertmanager.',
    'https://prometheus.io', 'https://prometheus.io/docs/', 'https://github.com/prometheus/prometheus', 'Apache-2.0',
    'Coleta de métricas de séries temporais via HTTP pull, avaliação de regras de alerta e observabilidade cloud-native.',
    ['Banco TSDB de alta performance', 'Linguagem PromQL', 'Service Discovery dinâmico', 'Exporters para Windows/Linux/SQL', 'Alertmanager integrado'],
    ['Linux', 'Windows', 'macOS', 'Docker', 'Kubernetes'], 'Binário Go / Container',
    ['SREs', 'Engenheiros DevOps', 'Arquitetos de Plataforma'],
    ['Grafana', 'Kubernetes', 'OpenTelemetry', 'Node Exporter', 'Windows Exporter'],
  ],
  [
    'Grafana', 'Grafana Labs', 'Monitoramento & Observabilidade',
    'Plataforma open-source de visualização analítica, dashboards operacionais, correlação de métricas, logs e traces.',
    'https://grafana.com', 'https://grafana.com/docs/', 'https://github.com/grafana/grafana', 'AGPL-3.0',
    'Visualização unificada de telemetria, observabilidade em tempo real e alertas multi-fonte.',
    ['Dashboards interativos', 'Conectores para Prometheus, Loki, SQL e Elastic', 'Alertas unificados', 'RBAC e autenticação OAuth/SAML', 'Provisionamento como código'],
    ['Linux', 'Windows', 'macOS', 'Docker'], 'On-Premise / Grafana Cloud',
    ['SREs', 'Equipes de Operações', 'Analistas de Performance'],
    ['Prometheus', 'Zabbix', 'PostgreSQL', 'Elasticsearch', 'OpenTelemetry'],
  ],
  [
    'Uptime Kuma', 'Louis Lam & Community', 'Monitoramento & Observabilidade',
    'Ferramenta auto-hospedada leve e open-source de monitoramento de disponibilidade (HTTP/TCP/Ping/DNS/Docker) com páginas de status.',
    'https://uptime.kuma.pet', 'https://github.com/louislam/uptime-kuma/wiki', 'https://github.com/louislam/uptime-kuma', 'MIT',
    'Monitoramento contínuo de uptime de APIs, serviços web, portas TCP, certificados TLS e containers.',
    ['Monitoramento HTTP/HTTPS/TCP/Ping/DNS', 'Notificações em 90+ canais', 'Status Pages públicas', 'Verificação de validade de certificado SSL', 'Interface reativa via WebSocket'],
    ['Linux', 'Windows', 'Docker'], 'Node.js / Docker Self-hosted',
    ['Desenvolvedores', 'SysAdmins', 'Equipes de Operações'],
    ['Telegram', 'Discord', 'Slack', 'Teams', 'Prometheus Metrics'],
  ],
  [
    'Netdata', 'Netdata Inc.', 'Monitoramento & Observabilidade',
    'Agente open-source distribuído de monitoramento de performance e saúde de sistemas e aplicações em tempo real (por segundo).',
    'https://www.netdata.cloud', 'https://learn.netdata.cloud', 'https://github.com/netdata/netdata', 'GPL-3.0',
    'Telemetria de hardware, CPU, memória, disco, rede e processos com resolução de 1 segundo e detecção de anomalias.',
    ['Coleta de métricas por segundo', 'Zero configuração inicial', ' mais de 800 coletores integrados', 'Baixo overhead em C', 'Dashboards em tempo real'],
    ['Linux', 'Windows', 'macOS', 'Docker'], 'Agente Local + Cloud Opcional',
    ['SysAdmins', 'Engenheiros de Performance', 'DevOps'],
    ['Prometheus', 'Grafana', 'PagerDuty', 'Slack'],
  ],

  // 5. Aplicações Desktop Windows / RMM / Gerenciamento & Otimização
  [
    'Tactical RMM', 'Amidaware', 'Aplicações Desktop Windows',
    'Plataforma open-source de monitoramento e gerenciamento remoto (RMM) para estações e servidores Windows e Linux.',
    'https://docs.tacticalrmm.com', 'https://docs.tacticalrmm.com', 'https://github.com/amidaware/tacticalrmm', 'AGPL-3.0',
    'Gerenciamento remoto de máquinas Windows, execução de scripts PowerShell, inventário de hardware/software, patches e suporte.',
    ['Agente nativo em Golang para Windows', 'Execução remota de scripts PowerShell/Batch', 'Gestão de Windows Update e patches', 'Monitoramento de serviços e eventos Windows', 'Acesso remoto integrado com MeshCentral'],
    ['Windows', 'Linux'], 'Servidor Self-hosted + Agente Windows',
    ['MSPs', 'Administradores de Redes Windows', 'Suporte Técnico'],
    ['MeshCentral', 'Chocolatey', 'WinGet', 'Webhooks'],
  ],
  [
    'MeshCentral', 'Ylian Saint-Hilaire / Open Source', 'Aplicações Desktop Windows',
    'Servidor web completo e open-source para gerenciamento remoto de computadores, terminal remoto, transferência de arquivos e desktop remoto.',
    'https://meshcentral.com', 'https://ylianst.github.io/MeshCentral/', 'https://github.com/Ylianst/MeshCentral', 'Apache-2.0',
    'Administração remota de computadores Windows/Linux, suporte técnico, inventário de dispositivos e telemetria.',
    ['Controle remoto de área de trabalho', 'Terminal e arquivos via navegador', 'Suporte Intel AMT vPro', 'Agente leve multiplataforma', 'Autenticação 2FA'],
    ['Windows', 'Linux', 'macOS'], 'On-Premise Node.js / Docker',
    ['Equipes de Suporte TI', 'Administradores de Sistemas', 'Helpdesk'],
    ['Tactical RMM', 'LDAP', 'SAML', 'MongoDB/PostgreSQL'],
  ],
  [
    'FleetDM', 'Fleet Device Management', 'Aplicações Desktop Windows',
    'Plataforma open-source de gerenciamento de endpoints (MDM/Osquery), inventário de vulnerabilidades e conformidade para Windows, macOS e Linux.',
    'https://fleetdm.com', 'https://fleetdm.com/docs', 'https://github.com/fleetdm/fleet', 'MIT / Enterprise',
    'Auditoria em tempo real de estações Windows/Linux/macOS via SQL (osquery), inventário de softwares instalados e verificação de políticas.',
    ['Consultas SQL em tempo real sobre endpoints', 'Detecção de CVEs em softwares instalados', 'Políticas de conformidade (CIS Benchmarks)', 'MDM para Windows e macOS', 'Execução remota de scripts'],
    ['Windows', 'Linux', 'macOS'], 'Self-hosted / Cloud',
    ['Engenheiros de Segurança Corporativa', 'IT Admins', 'SecOps'],
    ['Osquery', 'Jira', 'Zendesk', 'Splunk', 'GitHub'],
  ],
  [
    'RustDesk', 'RustDesk Team', 'Aplicações Desktop Windows',
    'Software open-source de acesso e suporte remoto escrito em Rust com servidor próprio auto-hospedável e criptografia ponta a ponta.',
    'https://rustdesk.com', 'https://rustdesk.com/docs/en/', 'https://github.com/rustdesk/rustdesk', 'AGPL-3.0',
    'Suporte técnico remoto, compartilhamento de tela de baixa latência e transferência segura de arquivos entre desktops.',
    ['Criptografia TLS 1.3 ponta-a-ponta', 'Servidor relay auto-hospedado (hbbs/hbbr)', 'Codec VP8/VP9/AV1 e hardware acceleration', 'Transferência de arquivos e área de transferência', 'Zero configuração para o cliente'],
    ['Windows', 'Linux', 'macOS', 'Android', 'iOS'], 'Executável Desktop + Servidor Self-hosted',
    ['Suporte Técnico', 'Administradores de TI', 'Empresas com Requisitos de Privacidade'],
    ['OIDC', 'LDAP', 'REST API'],
  ],
  [
    'BleachBit', 'Andrew Ziem', 'Aplicações Desktop Windows',
    'Utilitário open-source de limpeza de disco, otimização de sistema Windows/Linux e proteção de privacidade.',
    'https://www.bleachbit.org', 'https://docs.bleachbit.org', 'https://github.com/bleachbit/bleachbit', 'GPL-3.0',
    'Limpeza de arquivos temporários, cache de sistema, otimização de armazenamento e destruição segura de artefatos no Windows e Linux.',
    ['Regras CleanerML extensíveis', 'Shredding seguro de arquivos', 'Limpeza de registro e caches no Windows', 'Interface CLI para automação em lote', 'Sem adware ou telemetria'],
    ['Windows', 'Linux'], 'Instalador e Portátil Desktop',
    ['Técnicos de Suporte', 'Usuários Windows/Linux', 'SysAdmins'],
    ['Linha de Comando (CLI)', 'Winapp2.ini'],
  ],
  [
    'WinUtil (ChrisTitusTech)', 'Chris Titus Tech', 'Aplicações Desktop Windows',
    'Ferramenta open-source em PowerShell/WPF para automação de instalações, ajustes de performance, debloat e manutenção do Windows 10/11.',
    'https://christitus.com/windows-tool/', 'https://winutil.christitus.com', 'https://github.com/ChrisTitusTech/winutil', 'MIT',
    'Otimização do sistema operacional Windows, instalação automatizada de pacotes via WinGet, desativação de telemetria e reparo do sistema.',
    ['Instalação em lote via WinGet/Choco', 'Tweaks de performance e serviços Windows', 'Configuração segura de Windows Update', 'Painel de diagnóstico e reparo DISM/SFC', 'Exportação/importação de perfis JSON'],
    ['Windows 10', 'Windows 11', 'Windows Server'], 'Script/Executável PowerShell WPF',
    ['Administradores Windows', 'Técnicos de TI', 'Power Users'],
    ['WinGet', 'Chocolatey', 'PowerShell'],
  ],

  // 6. Aplicações Web & Mobile: Fitness / Saúde / Treinos
  [
    'Wger Workout Manager', 'Wger Open Source Community', 'Aplicações Mobile',
    'Aplicação open-source completa de gerenciamento de treinos, fichas de academia, nutrição, evolução corporal e catálogo de exercícios.',
    'https://wger.de', 'https://wger.readthedocs.io', 'https://github.com/wger-project/wger', 'AGPL-3.0',
    'Planejamento de treinos de musculação/fitness, registro de séries e cargas, controle nutricional de calorias e acompanhamento de evolução física.',
    ['Criador de rotinas e fichas de treino', 'Catálogo colaborativo de exercícios', 'Diário nutricional e cálculo de macronutrientes', 'Gráficos de evolução de peso e medidas', 'App Flutter Mobile + API REST completa'],
    ['Web', 'Android', 'iOS', 'Docker'], 'Self-hosted Docker / SaaS / Mobile App',
    ['Praticantes de Musculação', 'Personal Trainers', 'Academias', 'Desenvolvedores HealthTech'],
    ['REST API', 'OpenFoodFacts', 'Flutter Mobile Client'],
  ],
  [
    'FitNotes', 'James Gay', 'Aplicações Mobile',
    'Rastreador minimalista de treinos de academia, séries, repetições, recordes pessoais (PRs) e gráficos de volume de treino.',
    'https://www.fitnotesapp.com', 'https://www.fitnotesapp.com/#features', undefined, 'Gratuito / Proprietário',
    'Registro offline rápido de exercícios de musculação e cardio, cronômetro de descanso e análise de progressão de carga.',
    ['Log de séries, peso e repetições', 'Cálculo automático de 1RM e recordes', 'Cronômetro de descanso configurável', 'Exportação CSV e backup local SQLite', 'Estatísticas por grupo muscular'],
    ['Android', 'iOS'], 'Aplicativo Mobile Nativo',
    ['Atletas', 'Praticantes de Academia', 'Usuários de Fitness'],
    ['Exportação CSV', 'Backup em Nuvem'],
    [false, 'CLOSED_SOURCE'],
  ],
  [
    'Hevy', 'Hevy Studios', 'Aplicações Mobile',
    'Plataforma moderna de acompanhamento de treinos de academia, planejamento de rotinas, gráficos de força e comunidade fitness.',
    'https://www.hevyapp.com', 'https://www.hevyapp.com/features/', undefined, 'Comercial Proprietária',
    'Planejamento e rastreamento de treinos de musculação com métricas avançadas de volume muscular e aplicativo para Apple Watch / Wear OS.',
    ['Rastreamento de séries (Warmup, Drop, Failure)', 'Gráficos de distribuição muscular', 'Sincronização com Smartwatches', 'Plataforma para Personal Trainers (Hevy Coach)', 'API para integrações'],
    ['iOS', 'Android', 'Web', 'Apple Watch', 'Wear OS'], 'App Mobile + SaaS',
    ['Praticantes de Musculação', 'Treinadores', 'Entusiastas de Fitness'],
    ['Apple Health', 'Google Health Connect', 'Strava'],
    [false, 'CLOSED_SOURCE'],
  ],
  [
    'openScale', 'oliexdev', 'Aplicações Mobile',
    'Aplicativo Android open-source para monitoramento de peso, percentual de gordura, massa muscular e métricas corporais com suporte a balanças Bluetooth.',
    'https://github.com/oliexdev/openScale', 'https://github.com/oliexdev/openScale/wiki', 'https://github.com/oliexdev/openScale', 'GPL-3.0',
    'Monitoramento privado e offline de composição corporal, saúde e metas de condicionamento físico.',
    ['Conexão Bluetooth BLE com balanças inteligentes', 'Cálculo de IMC, TMB, gordura e massa magra', 'Banco SQLite 100% local sem nuvem', 'Gráficos históricos e tendências', 'Importação/Exportação CSV'],
    ['Android'], 'APK / F-Droid / Google Play',
    ['Usuários de Fitness', 'Entusiastas de Privacidade em Saúde'],
    ['Bluetooth GATT BLE', 'CSV Export'],
  ],

  // 7. Leitores Digitais, Mangás, Quadrinhos, Ebooks & Bibliotecas
  [
    'Komga', 'Gauthier Roebroeck', 'Documentação & Knowledge Base',
    'Servidor de mídia e leitor web open-source para mangás, quadrinhos (CBZ/CBR/PDF) e ebooks (EPUB) com suporte a OPDS e API REST.',
    'https://komga.org', 'https://komga.org/docs/introduction', 'https://github.com/gotson/komga', 'MIT',
    'Gerenciamento de biblioteca digital, catálogo e leitura de mangás, quadrinhos, webtoons e livros digitais.',
    ['Leitor web integrado para mangá (RTL, LTR, Webtoon)', 'Extração de metadados ComicInfo.xml e EPUB', 'Suporte a formatos CBZ, CBR, PDF e EPUB', 'Protocolo OPDS v1/v2 e Kobo Sync', 'Controle de progresso de leitura multi-usuário'],
    ['Windows', 'Linux', 'macOS', 'Docker', 'Web'], 'Servidor Self-hosted / Desktop / Docker',
    ['Leitores de Mangá e Quadrinhos', 'Colecionadores Digitais', 'Self-hosters'],
    ['Mihon / Tachiyomi', 'OPDS Clients', 'Kobo', 'REST API'],
  ],
  [
    'Kavita', 'KavitaReader Team', 'Documentação & Knowledge Base',
    'Servidor digital open-source rápido e moderno para leitura e organização de mangás, comics, light novels e ebooks (EPUB/PDF/CBZ).',
    'https://www.kavitareader.com', 'https://wiki.kavitareader.com', 'https://github.com/Kareadita/Kavita', 'GPL-3.0',
    'Servidor e leitor multiplataforma de mangás, quadrinhos e ebooks com leitores dedicados de imagem, PDF e EPUB.',
    ['Leitor nativo de Mangá, Webtoon e EPUB', 'Agrupamento automático de volumes e capítulos', 'Sincronização de progresso em tempo real', 'Estatísticas detalhadas de leitura', 'Indexação ultrarrápida em C# .NET'],
    ['Windows', 'Linux', 'macOS', 'Docker', 'Web'], 'Executável Multiplataforma / Docker',
    ['Leitores de Mangá e Light Novels', 'Bibliotecas Pessoais', 'Comunidades de Leitura'],
    ['OPDS', 'Mihon / Tachiyomi', 'Kavita+ Metadata', 'OIDC'],
  ],
  [
    'Mihon (Tachiyomi)', 'Mihon Open Source Project', 'Aplicações Mobile',
    'Leitor open-source de mangás e quadrinhos para Android com gerenciamento de biblioteca local, rastreamento de capítulos e leitura customizável.',
    'https://mihon.app', 'https://mihon.app/docs/guides/getting-started', 'https://github.com/mihonapp/mihon', 'Apache-2.0',
    'Leitura de mangás, manhwas e quadrinhos com modos de visualização configuráveis, download offline e sincronização com trackers.',
    ['Modos de leitura Paginado, Webtoon e Contínuo', 'Suporte a arquivos locais CBZ/ZIP/EPUB', 'Sincronização com MyAnimeList, AniList e Kitsu', 'Categorias, filtros e backups automáticos', 'Cortes automáticos de bordas de página'],
    ['Android'], 'APK Open-Source',
    ['Leitores de Mangá e Quadrinhos Mobile'],
    ['AniList', 'MyAnimeList', 'Komga', 'Kavita', 'Shikimori'],
  ],
  [
    'Calibre Web', 'Janeczku & Community', 'Documentação & Knowledge Base',
    'Aplicação web open-source para navegação, leitura no navegador e download de ebooks e quadrinhos utilizando banco de dados Calibre.',
    'https://github.com/janeczku/calibre-web', 'https://github.com/janeczku/calibre-web/wiki', 'https://github.com/janeczku/calibre-web', 'GPL-3.0',
    'Catalogação, conversão e leitura online de livros digitais, PDFs e quadrinhos.',
    ['Leitor EPUB, PDF e Comic no navegador', 'Busca de metadados externos', 'Envio direto para Kindle por e-mail', 'Catálogo OPDS e sincronização Kobo', 'Autenticação LDAP/OAuth'],
    ['Linux', 'Windows', 'Docker', 'Web'], 'Python Web App / Docker',
    ['Bibliotecas Digitais', 'Leitores de Ebooks', 'Educadores'],
    ['Calibre DB', 'Kobo', 'Kindle Send-to-Email', 'OPDS'],
  ],
  [
    'SumatraPDF', 'Krzysztof Kowalczyk', 'Aplicações Desktop Windows',
    'Leitor nativo ultrarrápido e open-source para Windows com suporte a PDF, ePub, MOBI, CBZ, CBR, DjVu e XPS.',
    'https://www.sumatrapdfreader.org', 'https://www.sumatrapdfreader.org/docs/SumatraPDF-documentation', 'https://github.com/sumatrapdfreader/sumatrapdf', 'GPL-3.0 / BSD',
    'Leitura instantânea de documentos PDF, ebooks e quadrinhos (CBZ/CBR) no desktop Windows com baixíssimo consumo de memória.',
    ['Inicialização instantânea em C++ nativo', 'Leitor de quadrinhos CBZ/CBR e ebooks EPUB', 'Anotações e destaques em PDF', 'Versão portátil em arquivo único', 'Atalhos de teclado estilo Vim'],
    ['Windows'], 'Executável Nativo Windows (Instalador / Portátil)',
    ['Usuários Windows', 'Pesquisadores', 'Leitores de PDFs e Quadrinhos'],
    ['LaTeX SyncTeX', 'Linha de Comando Windows'],
  ],

  // 8. Gerenciamento de Bancos de Dados, Backend & Cloud
  [
    'Supabase', 'Supabase Inc.', 'Gerenciamento de Bancos de Dados',
    'Plataforma Backend-as-a-Service (BaaS) open-source construída sobre PostgreSQL com autenticação, APIs REST/GraphQL instantâneas, Realtime e Storage.',
    'https://supabase.com', 'https://supabase.com/docs', 'https://github.com/supabase/supabase', 'Apache-2.0',
    'Provisionamento de banco PostgreSQL gerenciado, autenticação JWT/RLS, armazenamento de arquivos e Edge Functions.',
    ['PostgreSQL 100% dedicado com pgvector', 'Row Level Security (RLS)', 'APIs REST geradas via PostgREST', 'Subscrições Realtime via WebSockets', 'Supabase Studio SQL Editor'],
    ['Linux', 'Docker', 'Cloud SaaS'], 'Cloud SaaS / Self-hosted Docker',
    ['Desenvolvedores Full-Stack', 'Startups', 'Arquitetos de Software'],
    ['Next.js', 'React', 'Flutter', 'GitHub Actions', 'Terraform'],
  ],
  [
    'PocketBase', 'Gani Georgiev', 'Gerenciamento de Bancos de Dados',
    'Backend open-source em arquivo único (Go) com banco SQLite embarcado, subscrições em tempo real, autenticação e painel administrativo.',
    'https://pocketbase.io', 'https://pocketbase.io/docs/', 'https://github.com/pocketbase/pocketbase', 'MIT',
    'Backend embutido leve com banco de dados SQLite, autenticação OAuth2, API REST e armazenamento de arquivos.',
    ['Executável único em Go sem dependências', 'SQLite em modo WAL de alta concorrência', 'Autenticação de usuários e OAuth2', 'Extensível como framework Go ou via JS hooks', 'Backups automatizados S3'],
    ['Linux', 'Windows', 'macOS'], 'Binário Único Auto-hospedado',
    ['Desenvolvedores Indie', 'Aplicações Desktop/Mobile', 'Microsserviços'],
    ['S3 Storage', 'OAuth2 Providers', 'JavaScript/Dart SDK'],
  ],

  // 9. Endpoint Security, EDR, SIEM & Segurança de Rede/APIs
  [
    'Wazuh', 'Wazuh Inc.', 'Endpoint Security & EDR',
    'Plataforma open-source unificada de XDR e SIEM para proteção de endpoints Windows/Linux, detecção de intrusão, FIM e conformidade.',
    'https://wazuh.com', 'https://documentation.wazuh.com', 'https://github.com/wazuh/wazuh', 'GPL-2.0',
    'Monitoramento de integridade de arquivos (FIM), detecção de ameaças em endpoints, análise de logs SIEM e resposta ativa.',
    ['File Integrity Monitoring (FIM)', 'Detecção de vulnerabilidades em endpoints', 'Auditoria CIS e PCI-DSS', 'Resposta ativa a incidentes', 'Agente multiplataforma Windows/Linux/macOS'],
    ['Linux', 'Windows', 'macOS', 'Docker'], 'On-Premise / Cloud',
    ['SOC', 'Blue Teams', 'Engenheiros de Segurança'],
    ['OpenSearch', 'VirusTotal', 'TheHive', 'Slack', 'PagerDuty'],
  ],
  [
    'OWASP ZAP', 'ZAP Dev Team / Checkmarx', 'Segurança de APIs & Web Application Firewall',
    'Scanner open-source líder mundial para testes dinâmicos de segurança de aplicações web (DAST) e auditoria de APIs REST/GraphQL/OpenAPI.',
    'https://www.zaproxy.org', 'https://www.zaproxy.org/docs/', 'https://github.com/zaproxy/zaproxy', 'Apache-2.0',
    'Testes dinâmicos de segurança (DAST), inspeção de tráfego HTTP, fuzzing e auditoria automatizada de APIs e aplicações web.',
    ['Active & Passive DAST Scanning', 'Importação de especificações OpenAPI/Swagger e GraphQL', 'Spider tradicional e AJAX', 'Automação via YAML e Docker em CI/CD', 'Proxy interceptador avançado'],
    ['Windows', 'Linux', 'macOS', 'Docker'], 'Desktop / CLI / Container',
    ['Pentesters', 'Engenheiros de AppSec', 'QA de Segurança'],
    ['GitHub Actions', 'GitLab CI', 'Jenkins', 'SARIF'],
  ],
  [
    'CrowdSec', 'CrowdSec', 'VPN & Segurança de Rede',
    'Motor de segurança colaborativo e open-source que analisa comportamentos de tráfego e logs para bloquear ataques em firewalls, proxies e APIs.',
    'https://www.crowdsec.net', 'https://docs.crowdsec.net', 'https://github.com/crowdsecurity/crowdsec', 'MIT',
    'Prevenção de intrusão (IPS), WAF application security e bloqueio automatizado de IPs maliciosos e força bruta.',
    ['Detecção comportamental via cenários YAML', 'Bouncers para Nginx, Traefik, Cloudflare e Windows Firewall', 'Motor AppSec WAF com regras ModSecurity/CRS', 'Inteligência de ameaças comunitária (CTI)', 'Baixo consumo em Go'],
    ['Linux', 'Windows', 'FreeBSD', 'Docker', 'Kubernetes'], 'Agente Open-Source + Bouncers',
    ['SecOps', 'SysAdmins', 'Arquitetos de Rede'],
    ['Nginx', 'Traefik', 'Cloudflare', 'Windows Firewall', 'Prometheus'],
  ],

  // 10. Infraestrutura, Containers, API Gateways & Git
  [
    'Portainer', 'Portainer.io', 'Infraestrutura & Gestão de Cloud',
    'Plataforma de gerenciamento visual e governança para ambientes Docker, Swarm e Kubernetes.',
    'https://www.portainer.io', 'https://docs.portainer.io', 'https://github.com/portainer/portainer', 'Zlib / Enterprise',
    'Orquestração, deploy de stacks GitOps, inspeção de logs e controle de acesso RBAC sobre containers Docker e Kubernetes.',
    ['Gerenciamento de containers, imagens, volumes e redes', 'Deploy GitOps de Docker Compose e manifestos K8s', 'Terminal interativo no navegador', 'RBAC e logs de auditoria', 'Edge Agent para dispositivos remotos'],
    ['Linux', 'Windows', 'Docker', 'Kubernetes'], 'Container Self-hosted',
    ['DevOps', 'SysAdmins', 'Equipes de Plataforma'],
    ['Docker', 'Kubernetes', 'GitHub', 'GitLab', 'OAuth/LDAP'],
  ],
  [
    'Traefik Proxy', 'Traefik Labs', 'Infraestrutura & Gestão de Cloud',
    'Reverse proxy e ingress controller cloud-native open-source com descoberta automática de serviços e certificados Let’s Encrypt.',
    'https://traefik.io', 'https://doc.traefik.io/traefik/', 'https://github.com/traefik/traefik', 'MIT',
    'Roteamento dinâmico de microsserviços, balanceamento de carga, terminação TLS automática e middlewares de segurança.',
    ['Auto-discovery para Docker e Kubernetes', 'Let’s Encrypt ACME automático', 'Suporte HTTP/3, gRPC e TCP/UDP', 'Middlewares de Rate Limit, Auth e Headers', 'Métricas nativas Prometheus e OpenTelemetry'],
    ['Linux', 'Windows', 'macOS', 'Docker', 'Kubernetes'], 'Binário Go / Container',
    ['Arquitetos Cloud', 'DevOps', 'SREs'],
    ['Docker', 'Kubernetes', 'Consul', 'Prometheus', 'Let’s Encrypt'],
  ],
  [
    'Gitea', 'Gitea Limited / Open Source', 'Gerenciamento de Projetos & Tarefas',
    'Plataforma DevOps auto-hospedada leve e open-source em Go para hospedagem Git, revisão de código, projetos Kanban, pacotes e CI/CD (Gitea Actions).',
    'https://about.gitea.com', 'https://docs.gitea.com', 'https://github.com/go-gitea/gitea', 'MIT',
    'Hospedagem de repositórios Git, gestão de issues e projetos, registro de pacotes e pipelines CI/CD compatíveis com GitHub Actions.',
    ['Baixo consumo de memória em binário único Go', 'Gitea Actions CI/CD integrado', 'Quadros de projetos e milestones', 'Package Registry (npm, Docker, PyPI, Maven)', 'Autenticação LDAP/OAuth2/2FA'],
    ['Linux', 'Windows', 'macOS', 'Docker'], 'Binário Único / Docker Self-hosted',
    ['Equipes de Desenvolvimento', 'Empresas On-Premise', 'DevSecOps'],
    ['GitHub Actions Workflows', 'Sonar/MqrBridge', 'Jenkins', 'Drone CI', 'Slack'],
  ],
];

export const REAL_MARKET_SOFTWARE_CATALOG: MarketReferenceDatabaseEntry[] =
  MARKET_SOFTWARE_SEEDS.map(buildMarketSoftwareEntry);

function normalizeSearchText(input: string): string {
  return (input || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function extractMeaningfulTokens(input: string): string[] {
  const stopWords = new Set([
    'para', 'como', 'com', 'uma', 'uns', 'umas', 'dos', 'das', 'nos', 'nas', 'por',
    'pelo', 'pela', 'que', 'seu', 'sua', 'seus', 'suas', 'sistema', 'software',
    'aplicacao', 'aplicativo', 'ferramenta', 'plataforma', 'projeto', 'modulo',
    'with', 'from', 'that', 'this', 'and', 'for', 'the',
  ]);
  return normalizeSearchText(input)
    .split(/[^a-z0-9+#.-]+/)
    .filter((tok) => tok.length >= 3 && !stopWords.has(tok));
}

function detectMatchingSemanticClusters(text: string): string[] {
  const normalized = normalizeSearchText(text);
  const matched: string[] = [];
  for (const [clusterKey, keywords] of Object.entries(IDEA_SEMANTIC_CLUSTERS)) {
    const hasMatch = keywords.some((kw) => normalized.includes(normalizeSearchText(kw)));
    if (hasMatch) {
      matched.push(clusterKey);
    }
  }
  return matched;
}

export class MarketCompetitorDiscoveryEngine {
  /**
   * Calcula a similaridade técnica entre o software/ideia alvo e um candidato de mercado.
   */
  public static calculateTechnicalSimilarity(
    target: {
      name: string;
      category?: string;
      domainTags?: string[];
      description: string;
      purpose?: string;
      features?: string[];
      languages?: string[];
      architecture?: string;
      distributionModel?: string;
    },
    candidate: MarketReferenceDatabaseEntry,
    weights: MarketDiscoveryWeights = DEFAULT_MARKET_DISCOVERY_WEIGHTS
  ): {
    totalSimilarityPercent: number;
    breakdown: MarketCompetitorCandidate['similarityBreakdown'];
    matchReasons: string[];
    matchReasonSummary: string;
    equivalentFeatures: string[];
    distinctFeatures: string[];
  } {
    const matchReasons: string[] = [];
    const equivalentFeatures: string[] = [];
    const distinctFeatures: string[] = [];

    const targetCategory = target.category || target.domainTags?.[0] || '';
    const combinedTargetRaw = [
      target.name,
      targetCategory,
      ...(target.domainTags || []),
      target.purpose || '',
      target.description || '',
      ...(target.features || []),
      ...(target.languages || []),
      target.architecture || '',
    ].join(' ');
    const targetNorm = normalizeSearchText(combinedTargetRaw);
    const targetTokens = extractMeaningfulTokens(combinedTargetRaw);

    const candidateRaw = [
      candidate.name,
      candidate.category,
      candidate.primaryPurpose,
      candidate.description,
      ...candidate.features,
      ...candidate.targetAudience,
      ...candidate.platforms,
    ].join(' ');
    const candidateNorm = normalizeSearchText(candidateRaw);

    const targetClusters = detectMatchingSemanticClusters(combinedTargetRaw);
    const candidateClusters = detectMatchingSemanticClusters(candidateRaw);
    const sharedClusters = targetClusters.filter((c) => candidateClusters.includes(c));

    // Interseção de tokens funcionais reais
    const matchedTokens = Array.from(
      new Set(targetTokens.filter((tok) => candidateNorm.includes(tok)))
    );

    const isSameCategory =
      (targetCategory.length > 0 &&
        (normalizeSearchText(candidate.category).includes(normalizeSearchText(targetCategory)) ||
          normalizeSearchText(targetCategory).includes(normalizeSearchText(candidate.category)))) ||
      sharedClusters.length > 0;

    // 1. Finalidade Principal (Purpose - 30%)
    let purposeScore = isSameCategory ? 62 : 28;
    if (sharedClusters.length > 0) {
      purposeScore += 35;
    }
    if (matchedTokens.length > 0) {
      purposeScore += Math.min(25, matchedTokens.length * 6);
    }
    purposeScore = Math.max(20, Math.min(98, Math.round(purposeScore)));

    // 2. Funcionalidades (Features - 25%)
    for (const feat of candidate.features) {
      const featNorm = normalizeSearchText(feat);
      const featTokens = extractMeaningfulTokens(feat);
      const matches =
        featTokens.some((w) => targetNorm.includes(w)) ||
        (sharedClusters.length > 0 && featTokens.some((w) => candidateNorm.includes(w) && targetTokens.length > 0)) ||
        (featNorm.includes('cli') && targetNorm.includes('cli')) ||
        (featNorm.includes('criptografia') &&
          (targetNorm.includes('aes') || targetNorm.includes('crypto') || targetNorm.includes('pbkdf2') || targetNorm.includes('argon2')));
      if (matches) {
        equivalentFeatures.push(feat);
      } else {
        distinctFeatures.push(feat);
      }
    }

    let featuresScore =
      candidate.features.length > 0
        ? Math.round(Math.min(72, ((equivalentFeatures.length + 1) / candidate.features.length) * 68))
        : 45;
    if (sharedClusters.length > 0 || matchedTokens.length >= 2) {
      featuresScore += 25;
    }
    featuresScore = Math.max(20, Math.min(97, Math.round(featuresScore)));

    // 3. Público e Casos de Uso (Audience - 15%)
    let audienceMatches = 0;
    for (const aud of candidate.targetAudience) {
      if (targetNorm.includes(normalizeSearchText(aud))) audienceMatches += 1;
    }
    const audienceScore = audienceMatches > 0 ? 92 : sharedClusters.length > 0 ? 84 : 68;

    // 4. Plataforma & Compatibilidade (Platform - 10%)
    const hasPlatformOverlap = candidate.platforms.some((p) =>
      targetNorm.includes(normalizeSearchText(p))
    );
    const platformScore = hasPlatformOverlap ? 92 : 82;

    // 5. Modelo de Distribuição (Distribution - 10%)
    const isSameDistribution =
      Boolean(target.distributionModel) &&
      normalizeSearchText(candidate.distributionModel).includes(
        normalizeSearchText(target.distributionModel || '')
      );
    const distributionScore = isSameDistribution ? 95 : 76;

    // 6. Integrações & Ecossistema (Integrations - 10%)
    const integrationsScore = candidate.supportedIntegrations.length > 2 ? 86 : 72;

    const weightedTotal =
      (purposeScore * weights.purpose +
        featuresScore * weights.features +
        audienceScore * weights.audience +
        platformScore * weights.platform +
        distributionScore * weights.distribution +
        integrationsScore * weights.integrations) /
      100;

    const totalSimilarityPercent = Math.max(25, Math.min(99, Math.round(weightedTotal)));

    const highlightedTerms =
      matchedTokens.length > 0
        ? matchedTokens.slice(0, 5).join(', ')
        : sharedClusters.length > 0
          ? sharedClusters.join(', ')
          : candidate.category;

    const matchReasonSummary =
      sharedClusters.length > 0 || matchedTokens.length > 0
        ? `Compatível com a ideia do projeto pelos termos [${highlightedTerms}] e funcionalidades equivalentes em ${candidate.category}.`
        : `Referência técnica avaliada no domínio ${candidate.category} (${candidate.primaryPurpose}).`;

    matchReasons.push(matchReasonSummary);
    if (equivalentFeatures.length > 0) {
      matchReasons.push(`Recursos equivalentes comprovados: ${equivalentFeatures.slice(0, 3).join(', ')}.`);
    }

    return {
      totalSimilarityPercent,
      breakdown: {
        purpose: purposeScore,
        features: featuresScore,
        audience: audienceScore,
        platform: platformScore,
        distribution: distributionScore,
        integrations: integrationsScore,
        purposeMatch: purposeScore,
        featuresMatch: featuresScore,
        audienceMatch: audienceScore,
        platformMatch: platformScore,
        distributionMatch: distributionScore,
        integrationsMatch: integrationsScore,
      },
      matchReasons,
      matchReasonSummary,
      equivalentFeatures,
      distinctFeatures,
    };
  }

  public static getCatalogSize(): number {
    return REAL_MARKET_SOFTWARE_CATALOG.length;
  }

  public static getAvailableCategories(): readonly string[] {
    return MARKET_CATEGORIES;
  }

  /**
   * Descobre candidatos no mercado para o software ou ideia/propósito especificado.
   * Avalia todos os itens do catálogo sem descartar candidatos apenas porque a categoria
   * textual difere, priorizando similaridade semântica de ideia, propósito e funcionalidades.
   */
  public static discoverCompetitors(params: {
    targetSoftware?: {
      id: string;
      name: string;
      category: string;
      description: string;
      domainTags?: string[];
      languages?: string[];
      architecture?: string;
      distributionModel?: string;
    };
    category?: string;
    purpose?: string;
    features?: string[];
    audience?: string;
    platform?: string;
    distribution?: string;
    categoryOverride?: string;
    maxCandidates?: number;
  }): MarketCompetitorCandidate[] {
    const resolvedCategory =
      params.categoryOverride ||
      params.category ||
      params.targetSoftware?.category ||
      '';

    const combinedDescription = [
      params.purpose || '',
      params.targetSoftware?.description || '',
      ...(params.features || []),
      ...(params.targetSoftware?.domainTags || []),
    ]
      .filter(Boolean)
      .join(' ');

    const resolvedTarget = {
      id: params.targetSoftware?.id || 'target-dynamic',
      name: params.targetSoftware?.name || params.purpose || 'Software Alvo',
      category: resolvedCategory,
      domainTags: params.targetSoftware?.domainTags || params.features || [],
      purpose: params.purpose || '',
      description: combinedDescription,
      features: params.features || [],
      languages: params.targetSoftware?.languages || params.features || [],
      architecture: params.platform || params.targetSoftware?.architecture || 'Cross-platform',
      distributionModel: params.distribution || params.targetSoftware?.distributionModel || 'Cloud / On-Premise',
    };

    const maxCandidates = params.maxCandidates ?? 6;
    const nowIso = new Date().toISOString();

    const pool = REAL_MARKET_SOFTWARE_CATALOG.filter(
      (item) => item.name.toLowerCase() !== resolvedTarget.name.toLowerCase()
    );

    const scoredCandidates: MarketCompetitorCandidate[] = pool.map((entry) => {
      const sim = this.calculateTechnicalSimilarity(resolvedTarget, entry);
      const candidateId = `cand-${computeSha256(entry.name + entry.officialUrl).slice(0, 10)}`;

      const confidence: 'HIGH' | 'MEDIUM' | 'LOW' =
        entry.isOpenSource && entry.repositoryUrl
          ? 'HIGH'
          : entry.documentationUrl
            ? 'MEDIUM'
            : 'LOW';

      return {
        id: candidateId,
        name: entry.name,
        vendor: entry.vendor,
        version: 'Latest Official',
        description: entry.description,
        officialUrl: entry.officialUrl,
        documentationUrl: entry.documentationUrl,
        repositoryUrl: entry.repositoryUrl,
        publicRepoUrl: entry.repositoryUrl,
        marketSourceUrl: entry.officialUrl,
        category: entry.category,
        estimatedSimilarityPercent: sim.totalSimilarityPercent,
        similarityScore: sim.totalSimilarityPercent,
        computedMatchScore: sim.totalSimilarityPercent,
        similarityOrigin: 'HEURISTIC_METADATA_SIMILARITY',
        isMeasuredBenchmark: false,
        similarityDisclaimer:
          'Similaridade estimada exclusivamente por heurística de metadados de catálogo (HEURISTIC_METADATA_SIMILARITY) — não constitui benchmark técnico medido.',
        similarityBreakdown: sim.breakdown,
        matchReasons: sim.matchReasons,
        matchReasonSummary: sim.matchReasonSummary,
        equivalentFeatures: sim.equivalentFeatures,
        distinctFeatures: sim.distinctFeatures,
        featuresIdentified: entry.features,
        sources: [
          {
            title: `Documentação Oficial (${entry.vendor})`,
            url: entry.documentationUrl,
            date: nowIso.slice(0, 10),
            confidence: 'HIGH',
          },
          ...(entry.repositoryUrl
            ? [
                {
                  title: `Repositório Oficial de Código (${entry.repositoryUrl})`,
                  url: entry.repositoryUrl,
                  date: nowIso.slice(0, 10),
                  confidence: 'HIGH' as const,
                },
              ]
            : []),
        ],
        researchDate: nowIso,
        confidence,
        isOpenSource: entry.isOpenSource,
        openSource: entry.isOpenSource,
        sourceAvailability: entry.sourceAvailability,
        analysisScope: entry.sourceAvailability,
        approvedByUser: false,
      };
    });

    scoredCandidates.sort((a, b) => b.estimatedSimilarityPercent - a.estimatedSimilarityPercent);
    return scoredCandidates.slice(0, maxCandidates);
  }
}
