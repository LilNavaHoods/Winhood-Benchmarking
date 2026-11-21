/**
 * WinHood Canonical Benchmark Categories & Default Weights (Browser-Safe)
 *
 * Single source of truth shared between Frontend (BenchmarkWizardModule,
 * VeracityAdaptersReportsModule) and Backend (scoringEngine, marketCompetitorDiscoveryEngine).
 * Must remain 100% browser-safe (zero Node.js built-in imports).
 */

import type { BenchmarkCategoryKey } from '../types/benchmark';

export const ALL_BENCHMARK_CATEGORIES: BenchmarkCategoryKey[] = [
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

export const DEFAULT_CATEGORY_WEIGHTS: Record<BenchmarkCategoryKey, number> = {
  functionality: 12,
  code_quality: 12,
  security: 18,
  performance: 10,
  architecture: 10,
  database: 8,
  reliability: 8,
  compatibility: 5,
  usability: 5,
  installation: 4,
  privacy: 4,
  documentation: 4,
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

export type MarketCategory = (typeof MARKET_CATEGORIES)[number];
