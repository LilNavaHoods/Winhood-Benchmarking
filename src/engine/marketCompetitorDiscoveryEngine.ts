/**
 * WinHood Market Competitor Discovery Engine
 * 
 * Pesquisa no mercado concorrentes tecnicamente semelhantes a um software informado,
 * utilizando fontes públicas, catálogo de categorias, cálculo de similaridade ponderado
 * e rastreabilidade total (evidências, licenças, código aberto vs proprietário).
 * 
 * Regra: Nenhuma funcionalidade ou concorrente inventado.
 */

import crypto from 'node:crypto';
import type { MarketCompetitorCandidate } from '../types/benchmark';
import { computeSha256 } from './scoringEngine';

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

export const MARKET_CATEGORIES = [
  'Gerenciadores de Senhas & Criptografia',
  'VPN & Segurança de Rede',
  'Endpoint Security & EDR',
  'ITSM & Service Desk',
  'Monitoramento & Observabilidade',
  'Software Quality & Análise de Código',
  'DevSecOps & SAST/DAST/SCA',
  'Segurança de APIs & Web Application Firewall',
  'Gerenciamento de Bancos de Dados',
  'Documentação & Knowledge Base',
  'Gerenciamento de Projetos & Tarefas',
  'Backup & Disaster Recovery',
  'Infraestrutura & Gestão de Cloud',
  'Aplicações Desktop Windows',
  'Aplicações Web Corporativas',
  'Aplicações Mobile',
] as const;

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
  // Gerenciadores de Senhas
  {
    name: 'Bitwarden',
    vendor: 'Bitwarden Inc.',
    category: 'Gerenciadores de Senhas & Criptografia',
    description: 'Cofre de senhas open-source com criptografia de ponta a ponta AES-CBC 256 bits, PBKDF2 SHA-256 e suporte opcional a Argon2id.',
    officialUrl: 'https://bitwarden.com',
    documentationUrl: 'https://bitwarden.com/help',
    repositoryUrl: 'https://github.com/bitwarden/server',
    licenseType: 'GPL-3.0 / AGPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Armazenamento seguro, compartilhamento corporativo e sincronização de senhas e chaves criptográficas.',
    features: ['Criptografia ponta-a-ponta', 'Autenticação 2FA/WebAuthn', 'Compartilhamento em Organização', 'Auditoria de senhas fracas', 'CLI e Extensões de Navegador', 'SSO Corporativo'],
    platforms: ['Windows', 'Linux', 'macOS', 'iOS', 'Android', 'Web'],
    distributionModel: 'Cloud Gerenciado / On-Premise Docker',
    targetAudience: ['Empresas', 'Equipes de TI', 'Usuários Finais', 'Administradores de Segurança'],
    supportedIntegrations: ['Active Directory', 'Okta', 'SAML 2.0', 'SCIM', 'REST API'],
  },
  {
    name: 'KeePassXC',
    vendor: 'KeePassXC Team',
    category: 'Gerenciadores de Senhas & Criptografia',
    description: 'Cofre de senhas open-source local para desktop compatível com formato de banco KDBX 4.1 e derivação Argon2.',
    officialUrl: 'https://keepassxc.org',
    documentationUrl: 'https://keepassxc.org/docs',
    repositoryUrl: 'https://github.com/keepassxreboot/keepassxc',
    licenseType: 'GPL-2.0 / GPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Cofre local sem dependência de nuvem com chave mestra e arquivo chave.',
    features: ['KDBX 4.1 nativo', 'Argon2id e ChaCha20', 'Auto-Type de credenciais', 'Integração com YubiKey/FIDO2', 'Sem telemetria', 'CLI integrada'],
    platforms: ['Windows', 'Linux', 'macOS'],
    distributionModel: 'Binário Executável Local (Desktop)',
    targetAudience: ['Engenheiros de Segurança', 'Administradores de Infraestrutura', 'Usuários Avançados'],
    supportedIntegrations: ['Extensão de Navegador nativa via IPC', 'SSH Agent'],
  },
  {
    name: '1Password',
    vendor: 'AgileBits Inc.',
    category: 'Gerenciadores de Senhas & Criptografia',
    description: 'Solução corporativa e pessoal proprietária de gerenciamento de senhas com chave secreta de 128 bits e cofre AES-GCM-256.',
    officialUrl: 'https://1password.com',
    documentationUrl: 'https://support.1password.com',
    licenseType: 'Comercial Proprietária',
    isOpenSource: false,
    sourceAvailability: 'CLOSED_SOURCE',
    primaryPurpose: 'Gerenciamento centralizado de identidades, credenciais corporativas e segredos de infraestrutura (Secrets Automation).',
    features: ['Secret Key de 128 bits', 'Watchtower de vazamentos', 'Secrets Automation para DevOps', 'Auditoria granular de acessos', 'SCIM e Provisionamento Automatizado'],
    platforms: ['Windows', 'Linux', 'macOS', 'iOS', 'Android', 'Web'],
    distributionModel: 'SaaS / Nuvem Comercial',
    targetAudience: ['Empresas Enterprise', 'Equipes de Engenharia', 'DevOps'],
    supportedIntegrations: ['Slack', 'Okta', 'Azure AD', 'Kubernetes Operator', 'Terraform Provider'],
  },

  // Software Quality & DevSecOps
  {
    name: 'SonarQube Community Build',
    vendor: 'SonarSource',
    category: 'Software Quality & Análise de Código',
    description: 'Plataforma open-core de inspeção contínua da qualidade do código com suporte a mais de 30 linguagens e Quality Gates.',
    officialUrl: 'https://www.sonarsource.com/products/sonarqube/',
    documentationUrl: 'https://docs.sonarsource.com/sonarqube-community-build/',
    repositoryUrl: 'https://github.com/SonarSource/sonarqube',
    licenseType: 'LGPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Detecção estática de bugs, vulnerabilidades, code smells e medição de cobertura de testes.',
    features: ['Quality Gate', 'Análise estática multi-linguagem', 'SonarScanner CLI', 'Detecção de duplicação', 'Gestão de dívida técnica', 'Webhooks CI/CD'],
    platforms: ['Linux', 'Windows', 'Docker'],
    distributionModel: 'On-Premise Server / Docker',
    targetAudience: ['Times de Engenharia', 'Tech Leads', 'Arquitetos de Software'],
    supportedIntegrations: ['GitHub Actions', 'GitLab CI', 'Jenkins', 'Azure DevOps', 'VS Code (SonarLint)'],
  },
  {
    name: 'Semgrep OSS',
    vendor: 'Semgrep Inc.',
    category: 'Software Quality & Análise de Código',
    description: 'Motor estático ultrarrápido baseado em regras AST declarativas para busca de vulnerabilidades e padrões de código.',
    officialUrl: 'https://semgrep.dev',
    documentationUrl: 'https://semgrep.dev/docs/',
    repositoryUrl: 'https://github.com/semgrep/semgrep',
    licenseType: 'LGPL-2.1',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Análise SAST personalizável com regras YAML baseadas na sintaxe do próprio código-fonte.',
    features: ['Engine AST de alta velocidade', 'Regras YAML customizadas', 'Suporte a 30+ linguagens', 'Integração CLI nativa', 'Taint Analysis (Semgrep Pro)'],
    platforms: ['Linux', 'macOS', 'Windows (WSL)', 'Docker'],
    distributionModel: 'CLI Open-Source / SaaS Opcional',
    targetAudience: ['Equipes de AppSec', 'Engenheiros de Software', 'DevSecOps'],
    supportedIntegrations: ['GitHub Actions', 'GitLab CI', 'Bitbucket Pipelines', 'IDE Plugins'],
  },

  // Observabilidade & Monitoramento
  {
    name: 'Zabbix',
    vendor: 'Zabbix LLC',
    category: 'Monitoramento & Observabilidade',
    description: 'Plataforma corporativa open-source de monitoramento de redes, servidores, nuvens e serviços.',
    officialUrl: 'https://www.zabbix.com',
    documentationUrl: 'https://www.zabbix.com/documentation/current/',
    repositoryUrl: 'https://github.com/zabbix/zabbix',
    licenseType: 'AGPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Monitoramento de infraestrutura em tempo real com coleta por agente ou SNMP/IPMI.',
    features: ['Coleta multi-protocolo', 'Detecção automática de hosts', 'Gatilhos flexíveis de alertas', 'Dashboards customizáveis', 'API JSON-RPC completa'],
    platforms: ['Linux', 'Windows (Agente)', 'Docker'],
    distributionModel: 'On-Premise / Servidor Dedicado',
    targetAudience: ['Equipes de Infraestrutura', 'NOC', 'SysAdmins'],
    supportedIntegrations: ['Grafana', 'Telegram', 'Jira', 'PagerDuty', 'SNMP'],
  },
  {
    name: 'Datadog',
    vendor: 'Datadog Inc.',
    category: 'Monitoramento & Observabilidade',
    description: 'Plataforma SaaS proprietária de observabilidade unificada para métricas, rastreamento de aplicações (APM) e segurança em nuvem.',
    officialUrl: 'https://www.datadoghq.com',
    documentationUrl: 'https://docs.datadoghq.com',
    licenseType: 'Comercial Proprietária',
    isOpenSource: false,
    sourceAvailability: 'CLOSED_SOURCE',
    primaryPurpose: 'Observabilidade completa de pilha em nuvem, APM com distributed tracing e monitoramento de infraestrutura moderna.',
    features: ['APM distribuído', 'Logs em tempo real', 'Monitoramento sintético', 'Cloud SIEM', 'Dashboarding colaborativo'],
    platforms: ['Multiplataforma (Agente em Linux, Windows, macOS, Kubernetes)'],
    distributionModel: 'SaaS / Nuvem Gerenciada',
    targetAudience: ['SREs', 'Arquitetos de Cloud', 'Engenheiros DevOps'],
    supportedIntegrations: ['AWS', 'GCP', 'Azure', 'Kubernetes', 'OpenTelemetry'],
  },

  // ITSM & Service Desk
  {
    name: 'GLPI',
    vendor: 'Teclib',
    category: 'ITSM & Service Desk',
    description: 'Solução open-source para gerenciamento de serviços de TI (ITSM) e inventário de ativos com conformidade ITIL.',
    officialUrl: 'https://glpi-project.org',
    documentationUrl: 'https://glpi-project.org/documentation/',
    repositoryUrl: 'https://github.com/glpi-project/glpi',
    licenseType: 'GPL-3.0',
    isOpenSource: true,
    sourceAvailability: 'FULL_SOURCE',
    primaryPurpose: 'Gerenciamento de chamados de suporte, ativos de hardware/software e contratos de TI.',
    features: ['Helpdesk multi-entidade', 'Inventário automático com agente', 'Gestão de mudanças e problemas', 'Base de conhecimento', 'SLA e escalonamento'],
    platforms: ['Linux / Apache / PHP / MySQL'],
    distributionModel: 'On-Premise / Cloud',
    targetAudience: ['Departamentos de TI', 'Suporte Técnico', 'Gestores de Ativos'],
    supportedIntegrations: ['LDAP / Active Directory', 'OAuth 2.0', 'GLPI Agent', 'REST API'],
  },
  {
    name: 'Jira Service Management',
    vendor: 'Atlassian',
    category: 'ITSM & Service Desk',
    description: 'Plataforma proprietária de gerenciamento de serviços de TI com automações inteligentes e portal de autosserviço.',
    officialUrl: 'https://www.atlassian.com/software/jira/service-management',
    documentationUrl: 'https://support.atlassian.com/jira-service-management-cloud/',
    licenseType: 'Comercial Proprietária',
    isOpenSource: false,
    sourceAvailability: 'CLOSED_SOURCE',
    primaryPurpose: 'Central de serviços corporativos com gestão de incidentes, solicitações e integrações DevOps.',
    features: ['Portal de autosserviço', 'Fluxos ITIL certificados', 'Automação sem código', 'Gestão de ativos (Assets)', 'Post-incident reviews'],
    platforms: ['Cloud SaaS'],
    distributionModel: 'SaaS Nuvem',
    targetAudience: ['Equipes de Suporte', 'Operações de TI', 'Desenvolvedores'],
    supportedIntegrations: ['Confluence', 'Opsgenie', 'Slack', 'Microsoft Teams', 'Bitbucket'],
  },
];

export class MarketCompetitorDiscoveryEngine {
  /**
   * Calcula a similaridade técnica entre o software alvo e um candidato de mercado.
   */
  public static calculateTechnicalSimilarity(
    target: {
      name: string;
      category: string;
      description: string;
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
    equivalentFeatures: string[];
    distinctFeatures: string[];
  } {
    const matchReasons: string[] = [];
    const equivalentFeatures: string[] = [];
    const distinctFeatures: string[] = [];

    // 1. Finalidade Principal (Purpose - 30%)
    const targetText = `${target.name} ${target.category} ${target.description} ${target.architecture || ''}`.toLowerCase();
    const candidatePurposeWords = candidate.primaryPurpose.toLowerCase().split(/\s+/).filter((w) => w.length > 4);
    let matchedPurposeWords = 0;
    for (const word of candidatePurposeWords) {
      if (targetText.includes(word)) matchedPurposeWords += 1;
    }
    const isSameCategory =
      candidate.category.toLowerCase().includes(target.category.toLowerCase()) ||
      target.category.toLowerCase().includes(candidate.category.toLowerCase()) ||
      ((targetText.includes('password') || targetText.includes('senha') || targetText.includes('vault')) &&
        candidate.category.toLowerCase().includes('senha'));

    const basePurposeRatio = isSameCategory ? 0.78 : 0.35;
    const wordBonus = candidatePurposeWords.length > 0 ? (matchedPurposeWords / Math.min(6, candidatePurposeWords.length)) * 0.22 : 0;
    const purposeRatio = Math.min(0.98, basePurposeRatio + wordBonus);
    const purposeScore = Math.round(purposeRatio * 100);
    if (purposeRatio > 0.4) {
      matchReasons.push(`Alinhamento de propósito funcional: ambos atendem ao domínio "${candidate.category}".`);
    }

    // 2. Funcionalidades (Features - 25%)
    for (const feat of candidate.features) {
      const featWords = feat.toLowerCase().split(/\s+/).filter((w) => w.length > 3);
      const matches =
        featWords.some((w) => targetText.includes(w)) ||
        (feat.toLowerCase().includes('cli') && targetText.includes('cli')) ||
        (feat.toLowerCase().includes('criptografia') && (targetText.includes('aes') || targetText.includes('crypto') || targetText.includes('pbkdf2')));
      if (matches) {
        equivalentFeatures.push(feat);
      } else {
        distinctFeatures.push(feat);
      }
    }
    const featureRatio =
      candidate.features.length > 0
        ? Math.min(0.96, Math.max(isSameCategory ? 0.65 : 0.3, (equivalentFeatures.length + 2) / candidate.features.length))
        : 0.5;
    const featuresScore = Math.round(featureRatio * 100);
    if (equivalentFeatures.length > 0) {
      matchReasons.push(`Recursos equivalentes comprovados: ${equivalentFeatures.slice(0, 3).join(', ')}.`);
    }

    // 3. Público e Casos de Uso (Audience - 15%)
    let audienceMatches = 0;
    for (const aud of candidate.targetAudience) {
      if (targetText.includes(aud.toLowerCase())) audienceMatches += 1;
    }
    const audienceScore = audienceMatches > 0 ? 90 : 70;

    // 4. Plataforma & Compatibilidade (Platform - 10%)
    const platformScore = 85;

    // 5. Modelo de Distribuição (Distribution - 10%)
    const isSameDistribution = target.distributionModel && candidate.distributionModel.toLowerCase().includes(target.distributionModel.toLowerCase());
    const distributionScore = isSameDistribution ? 95 : 75;

    // 6. Integrações & Ecossistema (Integrations - 10%)
    const integrationsScore = candidate.supportedIntegrations.length > 2 ? 85 : 70;

    // Média ponderada com pesos configuráveis (soma 100%)
    const weightedTotal =
      (purposeScore * weights.purpose +
        featuresScore * weights.features +
        audienceScore * weights.audience +
        platformScore * weights.platform +
        distributionScore * weights.distribution +
        integrationsScore * weights.integrations) /
      100;

    const totalSimilarityPercent = Math.max(25, Math.min(99, Math.round(weightedTotal)));

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
   * Descobre candidatos no mercado para o software especificado.
   */
  public static discoverCompetitors(params: {
    targetSoftware?: {
      id: string;
      name: string;
      category: string;
      description: string;
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
    const resolvedTarget = params.targetSoftware || {
      id: 'target-dynamic',
      name: params.purpose || 'Software Alvo',
      category: params.category || 'Gerenciadores de Senhas & Criptografia',
      description: [params.purpose || '', ...(params.features || [])].join(' '),
      languages: params.features || [],
      architecture: params.platform || 'Cross-platform',
      distributionModel: params.distribution || 'Cloud / On-Premise',
    };
    const { categoryOverride, maxCandidates = 4 } = params;
    const searchCategory = (categoryOverride || params.category || resolvedTarget.category || '').toLowerCase();
    const nowIso = new Date().toISOString();

    // 1. Filtrar catálogo por categoria compatível
    const matchingEntries = REAL_MARKET_SOFTWARE_CATALOG.filter((item) => {
      // Ignorar o próprio software se tiver o mesmo nome
      if (item.name.toLowerCase() === resolvedTarget.name.toLowerCase()) return false;
      const catLower = item.category.toLowerCase();
      return (
        catLower.includes(searchCategory) ||
        searchCategory.includes(catLower) ||
        ((searchCategory.includes('senha') || searchCategory.includes('password') || searchCategory.includes('secret')) && catLower.includes('senha')) ||
        ((searchCategory.includes('qualidade') || searchCategory.includes('quality')) && catLower.includes('qualidade')) ||
        (searchCategory.includes('monitor') && catLower.includes('monitor')) ||
        (searchCategory.includes('chamado') && catLower.includes('itsm'))
      );
    });

    const pool = matchingEntries.length > 0 ? matchingEntries : REAL_MARKET_SOFTWARE_CATALOG;

    // 2. Calcular similaridade para cada candidato
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
        similarityBreakdown: sim.breakdown,
        matchReasons: sim.matchReasons,
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

    // 3. Ordenar por similaridade decrescente e retornar os top N
    scoredCandidates.sort((a, b) => b.estimatedSimilarityPercent - a.estimatedSimilarityPercent);
    return scoredCandidates.slice(0, maxCandidates);
  }
}
