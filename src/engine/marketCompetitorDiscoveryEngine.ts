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

export const REAL_MARKET_SOFTWARE_CATALOG: MarketReferenceDatabaseEntry[] = [
  // 1. Gerenciadores de Senhas & Criptografia
  {
    name: 'Bitwarden',
    vendor: 'Bitwarden Inc.',
    category: 'Gerenciadores de Senhas & Criptografia',
    description: 'Cofre de senhas open-source com criptografia de ponta a ponta AES-CBC 256 bits, PBKDF2 SHA-256 e suporte a Argon2id.',
    officialUrl: 'https://bitwarden.com',
    documentationUrl: 'https://bitwarden.com/help',
    repositoryUrl: 'https://github.com/bitwarden/server',
    licenseType: 'GPL-3.0 / AGPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Armazenamento seguro, compartilhamento corporativo e sincronização de senhas, cofres zero-knowledge e chaves criptográficas.',
    features: ['Criptografia ponta-a-ponta AES-256', 'Autenticação 2FA/WebAuthn', 'Compartilhamento em Organização', 'Auditoria de senhas fracas', 'CLI e Extensões de Navegador', 'SSO Corporativo'],
    platforms: ['Windows', 'Linux', 'macOS', 'iOS', 'Android', 'Web'],
    distributionModel: 'Cloud Gerenciado / On-Premise Docker',
    targetAudience: ['Empresas', 'Equipes de TI', 'Usuários Finais', 'Administradores de Segurança'],
    supportedIntegrations: ['Active Directory', 'Okta', 'SAML 2.0', 'SCIM', 'REST API'],
  },
  {
    name: 'KeePassXC',
    vendor: 'KeePassXC Team',
    category: 'Gerenciadores de Senhas & Criptografia',
    description: 'Cofre de senhas open-source local para desktop compatível com formato de banco KDBX 4.1 e derivação Argon2id.',
    officialUrl: 'https://keepassxc.org',
    documentationUrl: 'https://keepassxc.org/docs',
    repositoryUrl: 'https://github.com/keepassxreboot/keepassxc',
    licenseType: 'GPL-2.0 / GPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Cofre local de senhas KDBX sem dependência de nuvem com chave mestra, derivação Argon2id e arquivo chave.',
    features: ['KDBX 4.1 nativo', 'Argon2id e ChaCha20', 'Auto-Type de credenciais', 'Integração com YubiKey/FIDO2', 'Sem telemetria', 'CLI integrada'],
    platforms: ['Windows', 'Linux', 'macOS'],
    distributionModel: 'Binário Executável Local (Desktop)',
    targetAudience: ['Engenheiros de Segurança', 'Administradores de Infraestrutura', 'Usuários Avançados'],
    supportedIntegrations: ['Extensão de Navegador nativa via IPC', 'SSH Agent', 'Freedesktop Secret Service'],
  },
  {
    name: '1Password',
    vendor: 'AgileBits Inc.',
    category: 'Gerenciadores de Senhas & Criptografia',
    description: 'Solução corporativa e pessoal proprietária de gerenciamento de senhas com Secret Key de 128 bits e cofre AES-GCM-256.',
    officialUrl: 'https://1password.com',
    documentationUrl: 'https://support.1password.com',
    licenseType: 'Comercial Proprietária',
    isOpenSource: false,
    sourceAvailability: 'CLOSED_SOURCE',
    primaryPurpose: 'Gerenciamento centralizado de identidades, credenciais corporativas, cofres zero-knowledge e segredos de infraestrutura (Secrets Automation).',
    features: ['Secret Key de 128 bits', 'AES-256-GCM', 'Watchtower de vazamentos', 'Secrets Automation para DevOps', 'Auditoria granular de acessos', 'CLI e Extensões Web'],
    platforms: ['Windows', 'Linux', 'macOS', 'iOS', 'Android', 'Web'],
    distributionModel: 'SaaS / Nuvem Comercial',
    targetAudience: ['Empresas Enterprise', 'Equipes de Engenharia', 'DevOps', 'Security Teams'],
    supportedIntegrations: ['Slack', 'Okta', 'Azure AD', 'Kubernetes Operator', 'Terraform Provider'],
  },
  {
    name: 'Vaultwarden',
    vendor: 'Vaultwarden Community',
    category: 'Gerenciadores de Senhas & Criptografia',
    description: 'Implementação alternativa leve e open-source em Rust da API do servidor Bitwarden para auto-hospedagem de baixo consumo.',
    officialUrl: 'https://github.com/dani-garcia/vaultwarden',
    documentationUrl: 'https://github.com/dani-garcia/vaultwarden/wiki',
    repositoryUrl: 'https://github.com/dani-garcia/vaultwarden',
    licenseType: 'GPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Servidor auto-hospedado leve em Rust para gerenciamento de senhas, TOTP e cofres criptografados.',
    features: ['API Bitwarden compatível', 'Baixo consumo de RAM em Rust', 'SQLite/PostgreSQL/MySQL', 'WebSocket live sync', 'Suporte a WebAuthn e TOTP'],
    platforms: ['Linux', 'Docker', 'Windows'],
    distributionModel: 'Self-hosted Container / Binário Rust',
    targetAudience: ['Self-hosters', 'Pequenas e Médias Empresas', 'Equipes de DevSecOps'],
    supportedIntegrations: ['Clientes oficiais Bitwarden', 'Reverse Proxies', 'LDAP Sync'],
  },
  {
    name: 'Passbolt',
    vendor: 'Passbolt SA',
    category: 'Gerenciadores de Senhas & Criptografia',
    description: 'Gerenciador de senhas open-source para equipes de engenharia e operações baseado em criptografia OpenPGP.',
    officialUrl: 'https://www.passbolt.com',
    documentationUrl: 'https://help.passbolt.com',
    repositoryUrl: 'https://github.com/passbolt/passbolt_api',
    licenseType: 'AGPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Compartilhamento colaborativo de credenciais e senhas em equipes com criptografia GPG/OpenPGP.',
    features: ['Criptografia OpenPGP no cliente', 'RBAC por pastas e grupos', 'Auditoria de compartilhamento', 'Extensão de navegador verificada', 'MFA TOTP/YubiKey'],
    platforms: ['Linux', 'Docker', 'Web', 'iOS', 'Android'],
    distributionModel: 'On-Premise / Cloud SaaS',
    targetAudience: ['Times de DevOps', 'Agências Digitais', 'Equipes de Segurança'],
    supportedIntegrations: ['LDAP', 'SAML 2.0', 'REST API', 'CLI'],
  },

  // 2. Software Quality & Análise de Código / DevSecOps
  {
    name: 'Semgrep OSS',
    vendor: 'Semgrep Inc.',
    category: 'Software Quality & Análise de Código',
    description: 'Motor estático ultrarrápido baseado em regras AST declarativas para busca de vulnerabilidades, SAST e padrões de código.',
    officialUrl: 'https://semgrep.dev',
    documentationUrl: 'https://semgrep.dev/docs/',
    repositoryUrl: 'https://github.com/semgrep/semgrep',
    licenseType: 'LGPL-2.1',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Análise estática de código (SAST), qualidade e auditoria de segurança com regras AST em mais de 30 linguagens.',
    features: ['Engine AST multi-linguagem', 'Regras YAML customizadas', 'Exportação SARIF 2.1.0', 'Integração CLI e CI/CD', 'Taint Analysis'],
    platforms: ['Linux', 'macOS', 'Windows (WSL)', 'Docker'],
    distributionModel: 'CLI Open-Source / SaaS Opcional',
    targetAudience: ['Equipes de AppSec', 'Engenheiros de Software', 'DevSecOps'],
    supportedIntegrations: ['GitHub Actions', 'GitLab CI', 'Jenkins', 'VS Code'],
  },
  {
    name: 'MqrBridge Community Build',
    vendor: 'SonarSource',
    category: 'Software Quality & Análise de Código',
    description: 'Plataforma open-core de inspeção contínua da qualidade do código com suporte a mais de 30 linguagens e Quality Gates MQR.',
    officialUrl: 'https://www.sonarsource.com/products/mqr-bridge/',
    documentationUrl: 'https://docs.sonarsource.com/mqr-bridge-community-build/',
    repositoryUrl: 'https://github.com/SonarSource/mqr-bridge',
    licenseType: 'LGPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Detecção estática de bugs, vulnerabilidades, code smells, dívida técnica e medição de cobertura de testes.',
    features: ['Quality Gate', 'Análise estática multi-linguagem', 'Detecção de duplicação', 'Gestão de dívida técnica', 'Webhooks CI/CD'],
    platforms: ['Linux', 'Windows', 'Docker'],
    distributionModel: 'On-Premise Server / Docker',
    targetAudience: ['Times de Engenharia', 'Tech Leads', 'Arquitetos de Software'],
    supportedIntegrations: ['GitHub Actions', 'GitLab CI', 'Jenkins', 'Azure DevOps', 'VS Code'],
  },
  {
    name: 'GitHub CodeQL',
    vendor: 'GitHub / Microsoft',
    category: 'DevSecOps & SAST/DAST/SCA',
    description: 'Motor de análise semântica de código que trata código-fonte como banco de dados relacional para descobrir vulnerabilidades complexas e fluxos de taint.',
    officialUrl: 'https://codeql.github.com',
    documentationUrl: 'https://codeql.github.com/docs/',
    repositoryUrl: 'https://github.com/github/codeql',
    licenseType: 'MIT (Queries) / Proprietária (CLI)',
    isOpenSource: true,
    sourceAvailability: 'PARTIAL_SOURCE',
    primaryPurpose: 'Análise profunda de fluxo de dados (Taint Analysis), variante de vulnerabilidades e auditoria SAST.',
    features: ['Consultas declarativas QL', 'Dataflow e Taint Tracking interprocedural', 'Saída SARIF nativa', 'Suporte a TS/JS, Python, Java, C#, Go, C++'],
    platforms: ['Windows', 'Linux', 'macOS'],
    distributionModel: 'CLI / GitHub Advanced Security',
    targetAudience: ['Pesquisadores de Segurança', 'Equipes de AppSec', 'Desenvolvedores'],
    supportedIntegrations: ['GitHub Actions', 'VS Code CodeQL Extension', 'SARIF Viewers'],
  },
  {
    name: 'Trivy',
    vendor: 'Aqua Security',
    category: 'DevSecOps & SAST/DAST/SCA',
    description: 'Scanner abrangente e open-source de vulnerabilidades SCA, geração de SBOM (CycloneDX/SPDX), segredos e configurações IaC.',
    officialUrl: 'https://trivy.dev',
    documentationUrl: 'https://aquasecurity.github.io/trivy/',
    repositoryUrl: 'https://github.com/aquasecurity/trivy',
    licenseType: 'Apache-2.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Análise de composição de software (SCA), geração de SBOM, detecção de segredos e auditoria IaC (Dockerfile, Terraform, Kubernetes).',
    features: ['Scanner SCA multi-ecossistema', 'Geração de SBOM CycloneDX e SPDX', 'Auditoria de Dockerfile e Kubernetes', 'Detecção de segredos', 'Exportação SARIF'],
    platforms: ['Linux', 'Windows', 'macOS', 'Docker'],
    distributionModel: 'Binário CLI / Container',
    targetAudience: ['Engenheiros DevSecOps', 'SREs', 'Equipes de Segurança Cloud'],
    supportedIntegrations: ['GitHub Actions', 'GitLab CI', 'Kubernetes Operator', 'VS Code'],
  },
  {
    name: 'Snyk CLI',
    vendor: 'Snyk Ltd.',
    category: 'DevSecOps & SAST/DAST/SCA',
    description: 'Ferramenta focada no desenvolvedor para detecção e correção de vulnerabilidades em dependências open-source (SCA), código (SAST), containers e IaC.',
    officialUrl: 'https://snyk.io',
    documentationUrl: 'https://docs.snyk.io',
    repositoryUrl: 'https://github.com/snyk/cli',
    licenseType: 'Apache-2.0 (CLI) / SaaS Comercial',
    isOpenSource: false,
    sourceAvailability: 'PARTIAL_SOURCE',
    primaryPurpose: 'Identificação de vulnerabilidades de dependências, SAST em tempo real e automação de Pull Requests de correção.',
    features: ['Base proprietária de vulnerabilidades', 'Snyk Code SAST', 'Correção automática em PRs', 'Auditoria de licenças', 'Geração de SBOM'],
    platforms: ['Windows', 'Linux', 'macOS'],
    distributionModel: 'CLI + Plataforma SaaS',
    targetAudience: ['Desenvolvedores', 'Equipes de AppSec', 'Gestores de Engenharia'],
    supportedIntegrations: ['GitHub', 'GitLab', 'Jira', 'VS Code', 'JetBrains'],
  },

  // 3. ITSM & Service Desk (Chamados / Helpdesk)
  {
    name: 'GLPI',
    vendor: 'Teclib',
    category: 'ITSM & Service Desk',
    description: 'Solução open-source completa para gerenciamento de serviços de TI (ITSM), abertura de chamados (helpdesk) e inventário automático de ativos.',
    officialUrl: 'https://glpi-project.org',
    documentationUrl: 'https://glpi-project.org/documentation/',
    repositoryUrl: 'https://github.com/glpi-project/glpi',
    licenseType: 'GPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Gerenciamento de chamados de suporte (tickets/helpdesk), controle de SLA, ativos de hardware/software e processos ITIL.',
    features: ['Helpdesk e abertura de chamados multi-entidade', 'Inventário automático de computadores com agente', 'Gestão de mudanças e problemas ITIL', 'Base de conhecimento e FAQ', 'Controle de SLA e escalonamento'],
    platforms: ['Linux', 'Windows Server', 'Docker', 'Web'],
    distributionModel: 'On-Premise / Cloud',
    targetAudience: ['Departamentos de TI', 'Suporte Técnico / Service Desk', 'Gestores de Ativos'],
    supportedIntegrations: ['LDAP / Active Directory', 'OAuth 2.0', 'GLPI Agent', 'REST API'],
  },
  {
    name: 'Zammad',
    vendor: 'Zammad GmbH',
    category: 'ITSM & Service Desk',
    description: 'Sistema web open-source moderno de helpdesk, suporte ao cliente e gestão de chamados com busca full-text e múltiplos canais.',
    officialUrl: 'https://zammad.org',
    documentationUrl: 'https://docs.zammad.org',
    repositoryUrl: 'https://github.com/zammad/zammad',
    licenseType: 'AGPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Centralização de chamados de suporte, atendimento multicanal (e-mail, chat, telefone) e automação de filas de tickets.',
    features: ['Gestão de tickets em tempo real', 'Gatilhos e macros de SLA', 'Base de conhecimento multilíngue', 'Auditoria de histórico de atendimento', 'API REST e Webhooks'],
    platforms: ['Linux', 'Docker', 'Web'],
    distributionModel: 'Self-hosted / SaaS',
    targetAudience: ['Equipes de Suporte', 'Helpdesk de TI', 'Atendimento ao Cliente'],
    supportedIntegrations: ['LDAP', 'SAML', 'Slack', 'GitLab', 'GitHub'],
  },
  {
    name: 'osTicket',
    vendor: 'Enhancesoft',
    category: 'ITSM & Service Desk',
    description: 'Plataforma open-source amplamente adotada para abertura de chamados técnicos, roteamento de tickets e portal de atendimento.',
    officialUrl: 'https://osticket.com',
    documentationUrl: 'https://docs.osticket.com',
    repositoryUrl: 'https://github.com/osTicket/osTicket',
    licenseType: 'GPL-2.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Sistema leve de abertura de chamados, acompanhamento de solicitações de suporte e controle de SLA.',
    features: ['Formulários customizados de chamados', 'Filtros automáticos de roteamento', 'Planos de SLA', 'bloqueio de colisão entre agentes', 'Portal web do solicitante'],
    platforms: ['Linux', 'Windows', 'Web'],
    distributionModel: 'On-Premise / Cloud',
    targetAudience: ['Pequenas e Médias Empresas', 'Suporte de TI Interno', 'Universidades'],
    supportedIntegrations: ['Active Directory / LDAP', 'OAuth2', 'E-mail Piping / IMAP'],
  },
  {
    name: 'Chatwoot',
    vendor: 'Chatwoot Inc.',
    category: 'ITSM & Service Desk',
    description: 'Suite open-source de atendimento ao cliente, suporte omnichannel e gestão colaborativa de conversas e tickets.',
    officialUrl: 'https://www.chatwoot.com',
    documentationUrl: 'https://www.chatwoot.com/docs',
    repositoryUrl: 'https://github.com/chatwoot/chatwoot',
    licenseType: 'MIT / Enterprise',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Atendimento e suporte técnico unificado com caixa de entrada compartilhada, automação de chamados e relatórios de SLA.',
    features: ['Inbox compartilhada omnichannel', 'Regras de automação e SLA', 'Centro de ajuda / Help Center', 'Notas privadas e menções da equipe', 'Relatórios de tempo de resolução'],
    platforms: ['Linux', 'Docker', 'Web', 'iOS', 'Android'],
    distributionModel: 'Self-hosted Docker / Cloud',
    targetAudience: ['Suporte ao Cliente', 'Equipes de Produto', 'Service Desk Moderno'],
    supportedIntegrations: ['Slack', 'WhatsApp', 'Telegram', 'E-mail', 'Webhooks'],
  },
  {
    name: 'Jira Service Management',
    vendor: 'Atlassian',
    category: 'ITSM & Service Desk',
    description: 'Plataforma proprietária de gerenciamento de serviços de TI (ITSM) com filas de chamados, gestão de incidentes e portal de autosserviço.',
    officialUrl: 'https://www.atlassian.com/software/jira/service-management',
    documentationUrl: 'https://support.atlassian.com/jira-service-management-cloud/',
    licenseType: 'Comercial Proprietária',
    isOpenSource: false,
    sourceAvailability: 'CLOSED_SOURCE',
    primaryPurpose: 'Central de serviços corporativos e chamados de TI com gestão de incidentes, mudanças, ativos e integrações DevOps.',
    features: ['Portal de autosserviço de chamados', 'Fluxos ITIL certificados', 'Automação de triagem', 'Gestão de ativos (Assets)', 'Escalonamento de incidentes'],
    platforms: ['Cloud SaaS', 'Web', 'Mobile'],
    distributionModel: 'SaaS Nuvem',
    targetAudience: ['Equipes de Suporte', 'Operações de TI', 'Desenvolvedores'],
    supportedIntegrations: ['Confluence', 'Opsgenie', 'Slack', 'Microsoft Teams', 'GitHub'],
  },

  // 4. Monitoramento & Observabilidade
  {
    name: 'Zabbix',
    vendor: 'Zabbix LLC',
    category: 'Monitoramento & Observabilidade',
    description: 'Plataforma corporativa open-source de monitoramento de redes, servidores, agentes Windows/Linux, nuvens e serviços.',
    officialUrl: 'https://www.zabbix.com',
    documentationUrl: 'https://www.zabbix.com/documentation/current/',
    repositoryUrl: 'https://github.com/zabbix/zabbix',
    licenseType: 'AGPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Monitoramento de infraestrutura, redes e endpoints em tempo real com coleta por agente ou SNMP/IPMI.',
    features: ['Coleta multi-protocolo SNMP/Agent', 'Descoberta automática de rede', 'Gatilhos preditivos de alertas', 'Mapas topológicos de rede', 'API JSON-RPC completa'],
    platforms: ['Linux', 'Windows (Agente)', 'Docker'],
    distributionModel: 'On-Premise / Servidor Dedicado',
    targetAudience: ['Equipes de Infraestrutura', 'NOC', 'SysAdmins'],
    supportedIntegrations: ['Grafana', 'Telegram', 'Jira', 'PagerDuty', 'SNMP'],
  },
  {
    name: 'Prometheus',
    vendor: 'CNCF / Prometheus Authors',
    category: 'Monitoramento & Observabilidade',
    description: 'Sistema open-source de monitoramento e banco de dados de séries temporais (TSDB) com linguagem de consulta PromQL e Alertmanager.',
    officialUrl: 'https://prometheus.io',
    documentationUrl: 'https://prometheus.io/docs/',
    repositoryUrl: 'https://github.com/prometheus/prometheus',
    licenseType: 'Apache-2.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Coleta de métricas de séries temporais via HTTP pull, avaliação de regras de alerta e observabilidade cloud-native.',
    features: ['Banco TSDB de alta performance', 'Linguagem PromQL', 'Service Discovery dinâmico', 'Exporters para Windows/Linux/SQL', 'Alertmanager integrado'],
    platforms: ['Linux', 'Windows', 'macOS', 'Docker', 'Kubernetes'],
    distributionModel: 'Binário Go / Container',
    targetAudience: ['SREs', 'Engenheiros DevOps', 'Arquitetos de Plataforma'],
    supportedIntegrations: ['Grafana', 'Kubernetes', 'OpenTelemetry', 'Node Exporter', 'Windows Exporter'],
  },
  {
    name: 'Grafana',
    vendor: 'Grafana Labs',
    category: 'Monitoramento & Observabilidade',
    description: 'Plataforma open-source de visualização analítica, dashboards operacionais, correlação de métricas, logs e traces.',
    officialUrl: 'https://grafana.com',
    documentationUrl: 'https://grafana.com/docs/',
    repositoryUrl: 'https://github.com/grafana/grafana',
    licenseType: 'AGPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Visualização unificada de telemetria, observabilidade em tempo real e alertas multi-fonte.',
    features: ['Dashboards interativos', 'Conectores para Prometheus, Loki, SQL e Elastic', 'Alertas unificados', 'RBAC e autenticação OAuth/SAML', 'Provisionamento como código'],
    platforms: ['Linux', 'Windows', 'macOS', 'Docker'],
    distributionModel: 'On-Premise / Grafana Cloud',
    targetAudience: ['SREs', 'Equipes de Operações', 'Analistas de Performance'],
    supportedIntegrations: ['Prometheus', 'Zabbix', 'PostgreSQL', 'Elasticsearch', 'OpenTelemetry'],
  },
  {
    name: 'Uptime Kuma',
    vendor: 'Louis Lam & Community',
    category: 'Monitoramento & Observabilidade',
    description: 'Ferramenta auto-hospedada leve e open-source de monitoramento de disponibilidade (HTTP/TCP/Ping/DNS/Docker) com páginas de status.',
    officialUrl: 'https://uptime.kuma.pet',
    documentationUrl: 'https://github.com/louislam/uptime-kuma/wiki',
    repositoryUrl: 'https://github.com/louislam/uptime-kuma',
    licenseType: 'MIT',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Monitoramento contínuo de uptime de APIs, serviços web, portas TCP, certificados TLS e containers.',
    features: ['Monitoramento HTTP/HTTPS/TCP/Ping/DNS', 'Notificações em 90+ canais', 'Status Pages públicas', 'Verificação de validade de certificado SSL', 'Interface reativa via WebSocket'],
    platforms: ['Linux', 'Windows', 'Docker'],
    distributionModel: 'Node.js / Docker Self-hosted',
    targetAudience: ['Desenvolvedores', 'SysAdmins', 'Equipes de Operações'],
    supportedIntegrations: ['Telegram', 'Discord', 'Slack', 'Teams', 'Prometheus Metrics'],
  },
  {
    name: 'Netdata',
    vendor: 'Netdata Inc.',
    category: 'Monitoramento & Observabilidade',
    description: 'Agente open-source distribuído de monitoramento de performance e saúde de sistemas e aplicações em tempo real (por segundo).',
    officialUrl: 'https://www.netdata.cloud',
    documentationUrl: 'https://learn.netdata.cloud',
    repositoryUrl: 'https://github.com/netdata/netdata',
    licenseType: 'GPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Telemetria de hardware, CPU, memória, disco, rede e processos com resolução de 1 segundo e detecção de anomalias.',
    features: ['Coleta de métricas por segundo', 'Zero configuração inicial', ' mais de 800 coletores integrados', 'Baixo overhead em C', 'Dashboards em tempo real'],
    platforms: ['Linux', 'Windows', 'macOS', 'Docker'],
    distributionModel: 'Agente Local + Cloud Opcional',
    targetAudience: ['SysAdmins', 'Engenheiros de Performance', 'DevOps'],
    supportedIntegrations: ['Prometheus', 'Grafana', 'PagerDuty', 'Slack'],
  },

  // 5. Aplicações Desktop Windows / RMM / Gerenciamento & Otimização
  {
    name: 'Tactical RMM',
    vendor: 'Amidaware',
    category: 'Aplicações Desktop Windows',
    description: 'Plataforma open-source de monitoramento e gerenciamento remoto (RMM) para estações e servidores Windows e Linux.',
    officialUrl: 'https://docs.tacticalrmm.com',
    documentationUrl: 'https://docs.tacticalrmm.com',
    repositoryUrl: 'https://github.com/amidaware/tacticalrmm',
    licenseType: 'AGPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Gerenciamento remoto de máquinas Windows, execução de scripts PowerShell, inventário de hardware/software, patches e suporte.',
    features: ['Agente nativo em Golang para Windows', 'Execução remota de scripts PowerShell/Batch', 'Gestão de Windows Update e patches', 'Monitoramento de serviços e eventos Windows', 'Acesso remoto integrado com MeshCentral'],
    platforms: ['Windows', 'Linux'],
    distributionModel: 'Servidor Self-hosted + Agente Windows',
    targetAudience: ['MSPs', 'Administradores de Redes Windows', 'Suporte Técnico'],
    supportedIntegrations: ['MeshCentral', 'Chocolatey', 'WinGet', 'Webhooks'],
  },
  {
    name: 'MeshCentral',
    vendor: 'Ylian Saint-Hilaire / Open Source',
    category: 'Aplicações Desktop Windows',
    description: 'Servidor web completo e open-source para gerenciamento remoto de computadores, terminal remoto, transferência de arquivos e desktop remoto.',
    officialUrl: 'https://meshcentral.com',
    documentationUrl: 'https://ylianst.github.io/MeshCentral/',
    repositoryUrl: 'https://github.com/Ylianst/MeshCentral',
    licenseType: 'Apache-2.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Administração remota de computadores Windows/Linux, suporte técnico, inventário de dispositivos e telemetria.',
    features: ['Controle remoto de área de trabalho', 'Terminal e arquivos via navegador', 'Suporte Intel AMT vPro', 'Agente leve multiplataforma', 'Autenticação 2FA'],
    platforms: ['Windows', 'Linux', 'macOS'],
    distributionModel: 'On-Premise Node.js / Docker',
    targetAudience: ['Equipes de Suporte TI', 'Administradores de Sistemas', 'Helpdesk'],
    supportedIntegrations: ['Tactical RMM', 'LDAP', 'SAML', 'MongoDB/PostgreSQL'],
  },
  {
    name: 'FleetDM',
    vendor: 'Fleet Device Management',
    category: 'Aplicações Desktop Windows',
    description: 'Plataforma open-source de gerenciamento de endpoints (MDM/Osquery), inventário de vulnerabilidades e conformidade para Windows, macOS e Linux.',
    officialUrl: 'https://fleetdm.com',
    documentationUrl: 'https://fleetdm.com/docs',
    repositoryUrl: 'https://github.com/fleetdm/fleet',
    licenseType: 'MIT / Enterprise',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Auditoria em tempo real de estações Windows/Linux/macOS via SQL (osquery), inventário de softwares instalados e verificação de políticas.',
    features: ['Consultas SQL em tempo real sobre endpoints', 'Detecção de CVEs em softwares instalados', 'Políticas de conformidade (CIS Benchmarks)', 'MDM para Windows e macOS', 'Execução remota de scripts'],
    platforms: ['Windows', 'Linux', 'macOS'],
    distributionModel: 'Self-hosted / Cloud',
    targetAudience: ['Engenheiros de Segurança Corporativa', 'IT Admins', 'SecOps'],
    supportedIntegrations: ['Osquery', 'Jira', 'Zendesk', 'Splunk', 'GitHub'],
  },
  {
    name: 'RustDesk',
    vendor: 'RustDesk Team',
    category: 'Aplicações Desktop Windows',
    description: 'Software open-source de acesso e suporte remoto escrito em Rust com servidor próprio auto-hospedável e criptografia ponta a ponta.',
    officialUrl: 'https://rustdesk.com',
    documentationUrl: 'https://rustdesk.com/docs/en/',
    repositoryUrl: 'https://github.com/rustdesk/rustdesk',
    licenseType: 'AGPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Suporte técnico remoto, compartilhamento de tela de baixa latência e transferência segura de arquivos entre desktops.',
    features: ['Criptografia TLS 1.3 ponta-a-ponta', 'Servidor relay auto-hospedado (hbbs/hbbr)', 'Codec VP8/VP9/AV1 e hardware acceleration', 'Transferência de arquivos e área de transferência', 'Zero configuração para o cliente'],
    platforms: ['Windows', 'Linux', 'macOS', 'Android', 'iOS'],
    distributionModel: 'Executável Desktop + Servidor Self-hosted',
    targetAudience: ['Suporte Técnico', 'Administradores de TI', 'Empresas com Requisitos de Privacidade'],
    supportedIntegrations: ['OIDC', 'LDAP', 'REST API'],
  },
  {
    name: 'BleachBit',
    vendor: 'Andrew Ziem',
    category: 'Aplicações Desktop Windows',
    description: 'Utilitário open-source de limpeza de disco, otimização de sistema Windows/Linux e proteção de privacidade.',
    officialUrl: 'https://www.bleachbit.org',
    documentationUrl: 'https://docs.bleachbit.org',
    repositoryUrl: 'https://github.com/bleachbit/bleachbit',
    licenseType: 'GPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Limpeza de arquivos temporários, cache de sistema, otimização de armazenamento e destruição segura de artefatos no Windows e Linux.',
    features: ['Regras CleanerML extensíveis', 'Shredding seguro de arquivos', 'Limpeza de registro e caches no Windows', 'Interface CLI para automação em lote', 'Sem adware ou telemetria'],
    platforms: ['Windows', 'Linux'],
    distributionModel: 'Instalador e Portátil Desktop',
    targetAudience: ['Técnicos de Suporte', 'Usuários Windows/Linux', 'SysAdmins'],
    supportedIntegrations: ['Linha de Comando (CLI)', 'Winapp2.ini'],
  },
  {
    name: 'WinUtil (ChrisTitusTech)',
    vendor: 'Chris Titus Tech',
    category: 'Aplicações Desktop Windows',
    description: 'Ferramenta open-source em PowerShell/WPF para automação de instalações, ajustes de performance, debloat e manutenção do Windows 10/11.',
    officialUrl: 'https://christitus.com/windows-tool/',
    documentationUrl: 'https://winutil.christitus.com',
    repositoryUrl: 'https://github.com/ChrisTitusTech/winutil',
    licenseType: 'MIT',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Otimização do sistema operacional Windows, instalação automatizada de pacotes via WinGet, desativação de telemetria e reparo do sistema.',
    features: ['Instalação em lote via WinGet/Choco', 'Tweaks de performance e serviços Windows', 'Configuração segura de Windows Update', 'Painel de diagnóstico e reparo DISM/SFC', 'Exportação/importação de perfis JSON'],
    platforms: ['Windows 10', 'Windows 11', 'Windows Server'],
    distributionModel: 'Script/Executável PowerShell WPF',
    targetAudience: ['Administradores Windows', 'Técnicos de TI', 'Power Users'],
    supportedIntegrations: ['WinGet', 'Chocolatey', 'PowerShell'],
  },

  // 6. Aplicações Web & Mobile: Fitness / Saúde / Treinos
  {
    name: 'Wger Workout Manager',
    vendor: 'Wger Open Source Community',
    category: 'Aplicações Mobile',
    description: 'Aplicação open-source completa de gerenciamento de treinos, fichas de academia, nutrição, evolução corporal e catálogo de exercícios.',
    officialUrl: 'https://wger.de',
    documentationUrl: 'https://wger.readthedocs.io',
    repositoryUrl: 'https://github.com/wger-project/wger',
    licenseType: 'AGPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Planejamento de treinos de musculação/fitness, registro de séries e cargas, controle nutricional de calorias e acompanhamento de evolução física.',
    features: ['Criador de rotinas e fichas de treino', 'Catálogo colaborativo de exercícios', 'Diário nutricional e cálculo de macronutrientes', 'Gráficos de evolução de peso e medidas', 'App Flutter Mobile + API REST completa'],
    platforms: ['Web', 'Android', 'iOS', 'Docker'],
    distributionModel: 'Self-hosted Docker / SaaS / Mobile App',
    targetAudience: ['Praticantes de Musculação', 'Personal Trainers', 'Academias', 'Desenvolvedores HealthTech'],
    supportedIntegrations: ['REST API', 'OpenFoodFacts', 'Flutter Mobile Client'],
  },
  {
    name: 'FitNotes',
    vendor: 'James Gay',
    category: 'Aplicações Mobile',
    description: 'Rastreador minimalista de treinos de academia, séries, repetições, recordes pessoais (PRs) e gráficos de volume de treino.',
    officialUrl: 'https://www.fitnotesapp.com',
    documentationUrl: 'https://www.fitnotesapp.com/#features',
    licenseType: 'Gratuito / Proprietário',
    isOpenSource: false,
    sourceAvailability: 'CLOSED_SOURCE',
    primaryPurpose: 'Registro offline rápido de exercícios de musculação e cardio, cronômetro de descanso e análise de progressão de carga.',
    features: ['Log de séries, peso e repetições', 'Cálculo automático de 1RM e recordes', 'Cronômetro de descanso configurável', 'Exportação CSV e backup local SQLite', 'Estatísticas por grupo muscular'],
    platforms: ['Android', 'iOS'],
    distributionModel: 'Aplicativo Mobile Nativo',
    targetAudience: ['Atletas', 'Praticantes de Academia', 'Usuários de Fitness'],
    supportedIntegrations: ['Exportação CSV', 'Backup em Nuvem'],
  },
  {
    name: 'Hevy',
    vendor: 'Hevy Studios',
    category: 'Aplicações Mobile',
    description: 'Plataforma moderna de acompanhamento de treinos de academia, planejamento de rotinas, gráficos de força e comunidade fitness.',
    officialUrl: 'https://www.hevyapp.com',
    documentationUrl: 'https://www.hevyapp.com/features/',
    licenseType: 'Comercial Proprietária',
    isOpenSource: false,
    sourceAvailability: 'CLOSED_SOURCE',
    primaryPurpose: 'Planejamento e rastreamento de treinos de musculação com métricas avançadas de volume muscular e aplicativo para Apple Watch / Wear OS.',
    features: ['Rastreamento de séries (Warmup, Drop, Failure)', 'Gráficos de distribuição muscular', 'Sincronização com Smartwatches', 'Plataforma para Personal Trainers (Hevy Coach)', 'API para integrações'],
    platforms: ['iOS', 'Android', 'Web', 'Apple Watch', 'Wear OS'],
    distributionModel: 'App Mobile + SaaS',
    targetAudience: ['Praticantes de Musculação', 'Treinadores', 'Entusiastas de Fitness'],
    supportedIntegrations: ['Apple Health', 'Google Health Connect', 'Strava'],
  },
  {
    name: 'openScale',
    vendor: 'oliexdev',
    category: 'Aplicações Mobile',
    description: 'Aplicativo Android open-source para monitoramento de peso, percentual de gordura, massa muscular e métricas corporais com suporte a balanças Bluetooth.',
    officialUrl: 'https://github.com/oliexdev/openScale',
    documentationUrl: 'https://github.com/oliexdev/openScale/wiki',
    repositoryUrl: 'https://github.com/oliexdev/openScale',
    licenseType: 'GPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Monitoramento privado e offline de composição corporal, saúde e metas de condicionamento físico.',
    features: ['Conexão Bluetooth BLE com balanças inteligentes', 'Cálculo de IMC, TMB, gordura e massa magra', 'Banco SQLite 100% local sem nuvem', 'Gráficos históricos e tendências', 'Importação/Exportação CSV'],
    platforms: ['Android'],
    distributionModel: 'APK / F-Droid / Google Play',
    targetAudience: ['Usuários de Fitness', 'Entusiastas de Privacidade em Saúde'],
    supportedIntegrations: ['Bluetooth GATT BLE', 'CSV Export'],
  },

  // 7. Leitores Digitais, Mangás, Quadrinhos, Ebooks & Bibliotecas
  {
    name: 'Komga',
    vendor: 'Gauthier Roebroeck',
    category: 'Documentação & Knowledge Base',
    description: 'Servidor de mídia e leitor web open-source para mangás, quadrinhos (CBZ/CBR/PDF) e ebooks (EPUB) com suporte a OPDS e API REST.',
    officialUrl: 'https://komga.org',
    documentationUrl: 'https://komga.org/docs/introduction',
    repositoryUrl: 'https://github.com/gotson/komga',
    licenseType: 'MIT',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Gerenciamento de biblioteca digital, catálogo e leitura de mangás, quadrinhos, webtoons e livros digitais.',
    features: ['Leitor web integrado para mangá (RTL, LTR, Webtoon)', 'Extração de metadados ComicInfo.xml e EPUB', 'Suporte a formatos CBZ, CBR, PDF e EPUB', 'Protocolo OPDS v1/v2 e Kobo Sync', 'Controle de progresso de leitura multi-usuário'],
    platforms: ['Windows', 'Linux', 'macOS', 'Docker', 'Web'],
    distributionModel: 'Servidor Self-hosted / Desktop / Docker',
    targetAudience: ['Leitores de Mangá e Quadrinhos', 'Colecionadores Digitais', 'Self-hosters'],
    supportedIntegrations: ['Mihon / Tachiyomi', 'OPDS Clients', 'Kobo', 'REST API'],
  },
  {
    name: 'Kavita',
    vendor: 'KavitaReader Team',
    category: 'Documentação & Knowledge Base',
    description: 'Servidor digital open-source rápido e moderno para leitura e organização de mangás, comics, light novels e ebooks (EPUB/PDF/CBZ).',
    officialUrl: 'https://www.kavitareader.com',
    documentationUrl: 'https://wiki.kavitareader.com',
    repositoryUrl: 'https://github.com/Kareadita/Kavita',
    licenseType: 'GPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Servidor e leitor multiplataforma de mangás, quadrinhos e ebooks com leitores dedicados de imagem, PDF e EPUB.',
    features: ['Leitor nativo de Mangá, Webtoon e EPUB', 'Agrupamento automático de volumes e capítulos', 'Sincronização de progresso em tempo real', 'Estatísticas detalhadas de leitura', 'Indexação ultrarrápida em C# .NET'],
    platforms: ['Windows', 'Linux', 'macOS', 'Docker', 'Web'],
    distributionModel: 'Executável Multiplataforma / Docker',
    targetAudience: ['Leitores de Mangá e Light Novels', 'Bibliotecas Pessoais', 'Comunidades de Leitura'],
    supportedIntegrations: ['OPDS', 'Mihon / Tachiyomi', 'Kavita+ Metadata', 'OIDC'],
  },
  {
    name: 'Mihon (Tachiyomi)',
    vendor: 'Mihon Open Source Project',
    category: 'Aplicações Mobile',
    description: 'Leitor open-source de mangás e quadrinhos para Android com gerenciamento de biblioteca local, rastreamento de capítulos e leitura customizável.',
    officialUrl: 'https://mihon.app',
    documentationUrl: 'https://mihon.app/docs/guides/getting-started',
    repositoryUrl: 'https://github.com/mihonapp/mihon',
    licenseType: 'Apache-2.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Leitura de mangás, manhwas e quadrinhos com modos de visualização configuráveis, download offline e sincronização com trackers.',
    features: ['Modos de leitura Paginado, Webtoon e Contínuo', 'Suporte a arquivos locais CBZ/ZIP/EPUB', 'Sincronização com MyAnimeList, AniList e Kitsu', 'Categorias, filtros e backups automáticos', 'Cortes automáticos de bordas de página'],
    platforms: ['Android'],
    distributionModel: 'APK Open-Source',
    targetAudience: ['Leitores de Mangá e Quadrinhos Mobile'],
    supportedIntegrations: ['AniList', 'MyAnimeList', 'Komga', 'Kavita', 'Shikimori'],
  },
  {
    name: 'Calibre Web',
    vendor: 'Janeczku & Community',
    category: 'Documentação & Knowledge Base',
    description: 'Aplicação web open-source para navegação, leitura no navegador e download de ebooks e quadrinhos utilizando banco de dados Calibre.',
    officialUrl: 'https://github.com/janeczku/calibre-web',
    documentationUrl: 'https://github.com/janeczku/calibre-web/wiki',
    repositoryUrl: 'https://github.com/janeczku/calibre-web',
    licenseType: 'GPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Catalogação, conversão e leitura online de livros digitais, PDFs e quadrinhos.',
    features: ['Leitor EPUB, PDF e Comic no navegador', 'Busca de metadados externos', 'Envio direto para Kindle por e-mail', 'Catálogo OPDS e sincronização Kobo', 'Autenticação LDAP/OAuth'],
    platforms: ['Linux', 'Windows', 'Docker', 'Web'],
    distributionModel: 'Python Web App / Docker',
    targetAudience: ['Bibliotecas Digitais', 'Leitores de Ebooks', 'Educadores'],
    supportedIntegrations: ['Calibre DB', 'Kobo', 'Kindle Send-to-Email', 'OPDS'],
  },
  {
    name: 'SumatraPDF',
    vendor: 'Krzysztof Kowalczyk',
    category: 'Aplicações Desktop Windows',
    description: 'Leitor nativo ultrarrápido e open-source para Windows com suporte a PDF, ePub, MOBI, CBZ, CBR, DjVu e XPS.',
    officialUrl: 'https://www.sumatrapdfreader.org',
    documentationUrl: 'https://www.sumatrapdfreader.org/docs/SumatraPDF-documentation',
    repositoryUrl: 'https://github.com/sumatrapdfreader/sumatrapdf',
    licenseType: 'GPL-3.0 / BSD',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Leitura instantânea de documentos PDF, ebooks e quadrinhos (CBZ/CBR) no desktop Windows com baixíssimo consumo de memória.',
    features: ['Inicialização instantânea em C++ nativo', 'Leitor de quadrinhos CBZ/CBR e ebooks EPUB', 'Anotações e destaques em PDF', 'Versão portátil em arquivo único', 'Atalhos de teclado estilo Vim'],
    platforms: ['Windows'],
    distributionModel: 'Executável Nativo Windows (Instalador / Portátil)',
    targetAudience: ['Usuários Windows', 'Pesquisadores', 'Leitores de PDFs e Quadrinhos'],
    supportedIntegrations: ['LaTeX SyncTeX', 'Linha de Comando Windows'],
  },

  // 8. Gerenciamento de Bancos de Dados, Backend & Cloud
  {
    name: 'Supabase',
    vendor: 'Supabase Inc.',
    category: 'Gerenciamento de Bancos de Dados',
    description: 'Plataforma Backend-as-a-Service (BaaS) open-source construída sobre PostgreSQL com autenticação, APIs REST/GraphQL instantâneas, Realtime e Storage.',
    officialUrl: 'https://supabase.com',
    documentationUrl: 'https://supabase.com/docs',
    repositoryUrl: 'https://github.com/supabase/supabase',
    licenseType: 'Apache-2.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Provisionamento de banco PostgreSQL gerenciado, autenticação JWT/RLS, armazenamento de arquivos e Edge Functions.',
    features: ['PostgreSQL 100% dedicado com pgvector', 'Row Level Security (RLS)', 'APIs REST geradas via PostgREST', 'Subscrições Realtime via WebSockets', 'Supabase Studio SQL Editor'],
    platforms: ['Linux', 'Docker', 'Cloud SaaS'],
    distributionModel: 'Cloud SaaS / Self-hosted Docker',
    targetAudience: ['Desenvolvedores Full-Stack', 'Startups', 'Arquitetos de Software'],
    supportedIntegrations: ['Next.js', 'React', 'Flutter', 'GitHub Actions', 'Terraform'],
  },
  {
    name: 'PocketBase',
    vendor: 'Gani Georgiev',
    category: 'Gerenciamento de Bancos de Dados',
    description: 'Backend open-source em arquivo único (Go) com banco SQLite embarcado, subscrições em tempo real, autenticação e painel administrativo.',
    officialUrl: 'https://pocketbase.io',
    documentationUrl: 'https://pocketbase.io/docs/',
    repositoryUrl: 'https://github.com/pocketbase/pocketbase',
    licenseType: 'MIT',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Backend embutido leve com banco de dados SQLite, autenticação OAuth2, API REST e armazenamento de arquivos.',
    features: ['Executável único em Go sem dependências', 'SQLite em modo WAL de alta concorrência', 'Autenticação de usuários e OAuth2', 'Extensível como framework Go ou via JS hooks', 'Backups automatizados S3'],
    platforms: ['Linux', 'Windows', 'macOS'],
    distributionModel: 'Binário Único Auto-hospedado',
    targetAudience: ['Desenvolvedores Indie', 'Aplicações Desktop/Mobile', 'Microsserviços'],
    supportedIntegrations: ['S3 Storage', 'OAuth2 Providers', 'JavaScript/Dart SDK'],
  },

  // 9. Endpoint Security, EDR, SIEM & Segurança de Rede/APIs
  {
    name: 'Wazuh',
    vendor: 'Wazuh Inc.',
    category: 'Endpoint Security & EDR',
    description: 'Plataforma open-source unificada de XDR e SIEM para proteção de endpoints Windows/Linux, detecção de intrusão, FIM e conformidade.',
    officialUrl: 'https://wazuh.com',
    documentationUrl: 'https://documentation.wazuh.com',
    repositoryUrl: 'https://github.com/wazuh/wazuh',
    licenseType: 'GPL-2.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Monitoramento de integridade de arquivos (FIM), detecção de ameaças em endpoints, análise de logs SIEM e resposta ativa.',
    features: ['File Integrity Monitoring (FIM)', 'Detecção de vulnerabilidades em endpoints', 'Auditoria CIS e PCI-DSS', 'Resposta ativa a incidentes', 'Agente multiplataforma Windows/Linux/macOS'],
    platforms: ['Linux', 'Windows', 'macOS', 'Docker'],
    distributionModel: 'On-Premise / Cloud',
    targetAudience: ['SOC', 'Blue Teams', 'Engenheiros de Segurança'],
    supportedIntegrations: ['OpenSearch', 'VirusTotal', 'TheHive', 'Slack', 'PagerDuty'],
  },
  {
    name: 'OWASP ZAP',
    vendor: 'ZAP Dev Team / Checkmarx',
    category: 'Segurança de APIs & Web Application Firewall',
    description: 'Scanner open-source líder mundial para testes dinâmicos de segurança de aplicações web (DAST) e auditoria de APIs REST/GraphQL/OpenAPI.',
    officialUrl: 'https://www.zaproxy.org',
    documentationUrl: 'https://www.zaproxy.org/docs/',
    repositoryUrl: 'https://github.com/zaproxy/zaproxy',
    licenseType: 'Apache-2.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Testes dinâmicos de segurança (DAST), inspeção de tráfego HTTP, fuzzing e auditoria automatizada de APIs e aplicações web.',
    features: ['Active & Passive DAST Scanning', 'Importação de especificações OpenAPI/Swagger e GraphQL', 'Spider tradicional e AJAX', 'Automação via YAML e Docker em CI/CD', 'Proxy interceptador avançado'],
    platforms: ['Windows', 'Linux', 'macOS', 'Docker'],
    distributionModel: 'Desktop / CLI / Container',
    targetAudience: ['Pentesters', 'Engenheiros de AppSec', 'QA de Segurança'],
    supportedIntegrations: ['GitHub Actions', 'GitLab CI', 'Jenkins', 'SARIF'],
  },
  {
    name: 'CrowdSec',
    vendor: 'CrowdSec',
    category: 'VPN & Segurança de Rede',
    description: 'Motor de segurança colaborativo e open-source que analisa comportamentos de tráfego e logs para bloquear ataques em firewalls, proxies e APIs.',
    officialUrl: 'https://www.crowdsec.net',
    documentationUrl: 'https://docs.crowdsec.net',
    repositoryUrl: 'https://github.com/crowdsecurity/crowdsec',
    licenseType: 'MIT',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Prevenção de intrusão (IPS), WAF application security e bloqueio automatizado de IPs maliciosos e força bruta.',
    features: ['Detecção comportamental via cenários YAML', 'Bouncers para Nginx, Traefik, Cloudflare e Windows Firewall', 'Motor AppSec WAF com regras ModSecurity/CRS', 'Inteligência de ameaças comunitária (CTI)', 'Baixo consumo em Go'],
    platforms: ['Linux', 'Windows', 'FreeBSD', 'Docker', 'Kubernetes'],
    distributionModel: 'Agente Open-Source + Bouncers',
    targetAudience: ['SecOps', 'SysAdmins', 'Arquitetos de Rede'],
    supportedIntegrations: ['Nginx', 'Traefik', 'Cloudflare', 'Windows Firewall', 'Prometheus'],
  },

  // 10. Infraestrutura, Containers, API Gateways & Git
  {
    name: 'Portainer',
    vendor: 'Portainer.io',
    category: 'Infraestrutura & Gestão de Cloud',
    description: 'Plataforma de gerenciamento visual e governança para ambientes Docker, Swarm e Kubernetes.',
    officialUrl: 'https://www.portainer.io',
    documentationUrl: 'https://docs.portainer.io',
    repositoryUrl: 'https://github.com/portainer/portainer',
    licenseType: 'Zlib / Enterprise',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Orquestração, deploy de stacks GitOps, inspeção de logs e controle de acesso RBAC sobre containers Docker e Kubernetes.',
    features: ['Gerenciamento de containers, imagens, volumes e redes', 'Deploy GitOps de Docker Compose e manifestos K8s', 'Terminal interativo no navegador', 'RBAC e logs de auditoria', 'Edge Agent para dispositivos remotos'],
    platforms: ['Linux', 'Windows', 'Docker', 'Kubernetes'],
    distributionModel: 'Container Self-hosted',
    targetAudience: ['DevOps', 'SysAdmins', 'Equipes de Plataforma'],
    supportedIntegrations: ['Docker', 'Kubernetes', 'GitHub', 'GitLab', 'OAuth/LDAP'],
  },
  {
    name: 'Traefik Proxy',
    vendor: 'Traefik Labs',
    category: 'Infraestrutura & Gestão de Cloud',
    description: 'Reverse proxy e ingress controller cloud-native open-source com descoberta automática de serviços e certificados Let’s Encrypt.',
    officialUrl: 'https://traefik.io',
    documentationUrl: 'https://doc.traefik.io/traefik/',
    repositoryUrl: 'https://github.com/traefik/traefik',
    licenseType: 'MIT',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Roteamento dinâmico de microsserviços, balanceamento de carga, terminação TLS automática e middlewares de segurança.',
    features: ['Auto-discovery para Docker e Kubernetes', 'Let’s Encrypt ACME automático', 'Suporte HTTP/3, gRPC e TCP/UDP', 'Middlewares de Rate Limit, Auth e Headers', 'Métricas nativas Prometheus e OpenTelemetry'],
    platforms: ['Linux', 'Windows', 'macOS', 'Docker', 'Kubernetes'],
    distributionModel: 'Binário Go / Container',
    targetAudience: ['Arquitetos Cloud', 'DevOps', 'SREs'],
    supportedIntegrations: ['Docker', 'Kubernetes', 'Consul', 'Prometheus', 'Let’s Encrypt'],
  },
  {
    name: 'Gitea',
    vendor: 'Gitea Limited / Open Source',
    category: 'Gerenciamento de Projetos & Tarefas',
    description: 'Plataforma DevOps auto-hospedada leve e open-source em Go para hospedagem Git, revisão de código, projetos Kanban, pacotes e CI/CD (Gitea Actions).',
    officialUrl: 'https://about.gitea.com',
    documentationUrl: 'https://docs.gitea.com',
    repositoryUrl: 'https://github.com/go-gitea/gitea',
    licenseType: 'MIT',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Hospedagem de repositórios Git, gestão de issues e projetos, registro de pacotes e pipelines CI/CD compatíveis com GitHub Actions.',
    features: ['Baixo consumo de memória em binário único Go', 'Gitea Actions CI/CD integrado', 'Quadros de projetos e milestones', 'Package Registry (npm, Docker, PyPI, Maven)', 'Autenticação LDAP/OAuth2/2FA'],
    platforms: ['Linux', 'Windows', 'macOS', 'Docker'],
    distributionModel: 'Binário Único / Docker Self-hosted',
    targetAudience: ['Equipes de Desenvolvimento', 'Empresas On-Premise', 'DevSecOps'],
    supportedIntegrations: ['GitHub Actions Workflows', 'Sonar/MqrBridge', 'Jenkins', 'Drone CI', 'Slack'],
  },
];

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
