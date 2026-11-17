import fs from 'node:fs';
import path from 'node:path';

export type CoverageDomainId =
  | 'src/analyzers/'
  | 'src/engine/'
  | 'src/scoring/'
  | 'src/evidence/'
  | 'src/comparability/'
  | 'src/gate/'
  | 'src/security/'
  | 'src/execution/'
  | 'src/integrations/'
  | 'src/reports/'
  | 'src/components/'
  | 'src/desktop/'
  | 'packages/vscode-extension/';

export interface CoverageDomainDescriptor {
  id: CoverageDomainId;
  name: string;
  responsibility: string;
  directories: string[];
  eligibleExtensions: string[];
  excludedPatterns: Array<{ pattern: string; justification: string }>;
  testingStrategy: string;
  acceptanceCriteria: {
    minLinesPct: number;
    minFunctionsPct: number;
    minBranchesPct: number;
    minStatementsPct: number;
    tier: 'CRITICAL_MOTOR' | 'CORE_SECURITY_ENGINE' | 'INTEGRATION_AND_UI';
  };
}

export interface DomainInventoryFileScan {
  domainId: CoverageDomainId;
  descriptor: CoverageDomainDescriptor;
  eligibleFiles: string[];
  excludedFiles: Array<{ filePath: string; reason: string }>;
}

export interface SeparatedTestCoverageMetric {
  indicatorType: 'TEST_COVERAGE';
  methodology: 'V8_SOURCEMAP_CONVENTIONAL';
  sourceMapValidated: boolean;
  instrumentedFilesCount: number;
  uninstrumentedFilesCount: number;
  uninstrumentedFiles: string[];
  statements: { total: number; covered: number; pct: number | null };
  lines: { total: number; covered: number; pct: number | null };
  functions: { total: number; covered: number; pct: number | null };
  branches: { total: number; covered: number; pct: number | null };
}

export interface SeparatedIngestionCoverageMetric {
  indicatorType: 'INGESTION_COVERAGE';
  discoveredFilesCount: number;
  eligibleFilesCount: number;
  ingestedFilesCount: number;
  excludedFilesCount: number;
  failedIngestionFilesCount: number;
  ingestionCoveragePct: number | null;
  status: 'COMPLETE' | 'PARTIAL' | 'NOT_INGESTED' | 'FAILED';
}

export interface SeparatedAnalysisCoverageMetric {
  indicatorType: 'ANALYSIS_COVERAGE';
  eligibleFilesCount: number;
  analyzedFilesCount: number;
  fullAstFilesCount: number;
  structuralAstFilesCount: number;
  partialRecoveryFilesCount: number;
  failedParseFilesCount: number;
  unsupportedFilesCount: number;
  analysisCoveragePct: number | null;
  fullAstRatioPct: number | null;
  status: 'COMPLETE' | 'PARTIAL' | 'NOT_ANALYZED' | 'FAILED';
}

export interface ThreeWaySeparatedCoverageBundle {
  separatedIndicatorsNote: string;
  testCoverage: SeparatedTestCoverageMetric;
  ingestionCoverage: SeparatedIngestionCoverageMetric;
  analysisCoverage: SeparatedAnalysisCoverageMetric;
}

export const OFFICIAL_13_COVERAGE_DOMAINS: readonly CoverageDomainDescriptor[] = [
  {
    id: 'src/analyzers/',
    name: 'Analisadores Estáticos, AST, Taint, Segredos e SCA/SBOM',
    responsibility:
      'Parsing AST/estrutural multi-linguagem, análise de fluxo de dados (Taint), catálogo de regras SAST/MQR, detecção de segredos, correlação SCA e geração de SBOM.',
    directories: ['src/analyzers'],
    eligibleExtensions: ['.ts'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Arquivos de suíte de teste automatizado (não compõem o denominador de produção).' },
      { pattern: '**/types.ts', justification: 'Declarações puras de tipos TypeScript sem instruções executáveis em runtime.' },
    ],
    testingStrategy: 'Testes unitários e de integração com casos positivos/negativos por linguagem, sanitizadores contextuais e SBOM.',
    acceptanceCriteria: {
      minLinesPct: 80,
      minFunctionsPct: 80,
      minBranchesPct: 75,
      minStatementsPct: 80,
      tier: 'CORE_SECURITY_ENGINE',
    },
  },
  {
    id: 'src/engine/',
    name: 'Orquestrador de Benchmark, Scoring Multidimensional e Proveniência',
    responsibility:
      'Orquestração de execuções, cálculo determinístico das 12 dimensões, cadeia de evidências SHA-256 e catálogo metodológico.',
    directories: ['src/engine'],
    eligibleExtensions: ['.ts'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Suítes de teste automatizado.' },
    ],
    testingStrategy: 'Testes determinísticos bit-a-bit, autoauditoria e validação de proveniência.',
    acceptanceCriteria: {
      minLinesPct: 80,
      minFunctionsPct: 80,
      minBranchesPct: 75,
      minStatementsPct: 80,
      tier: 'CORE_SECURITY_ENGINE',
    },
  },
  {
    id: 'src/scoring/',
    name: 'Motor Crítico de Pontuação e Penalidades',
    responsibility:
      'Agregação matemática ponderada, aplicação de Penalty Caps e classificação em escala 0.00–5.00.',
    directories: ['src/scoring'],
    eligibleExtensions: ['.ts'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Suítes de teste automatizado.' },
    ],
    testingStrategy: 'Testes unitários exaustivos de fronteira, pesos nulos, caps críticos e métricas ausentes.',
    acceptanceCriteria: {
      minLinesPct: 95,
      minFunctionsPct: 95,
      minBranchesPct: 95,
      minStatementsPct: 95,
      tier: 'CRITICAL_MOTOR',
    },
  },
  {
    id: 'src/evidence/',
    name: 'Motor Crítico de Cadeia de Evidências e Assinaturas',
    responsibility:
      'Geração e verificação de manifestos assinados (HMAC-SHA256 e Ed25519) e encadeamento criptográfico.',
    directories: ['src/evidence'],
    eligibleExtensions: ['.ts'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Suítes de teste automatizado.' },
    ],
    testingStrategy: 'Testes de integridade, detecção de adulteração, rotação de chaves e Trust Store Ed25519.',
    acceptanceCriteria: {
      minLinesPct: 95,
      minFunctionsPct: 95,
      minBranchesPct: 95,
      minStatementsPct: 95,
      tier: 'CRITICAL_MOTOR',
    },
  },
  {
    id: 'src/comparability/',
    name: 'Motor Crítico de Comparabilidade A/B Bimodal',
    responsibility:
      'Validação de equivalência intraclasse (mesmo motor) e interferramentas (ferramentas distintas) nos estados STRICTLY_COMPARABLE, QUALIFIED_COMPARISON e NOT_COMPARABLE.',
    directories: ['src/comparability'],
    eligibleExtensions: ['.ts'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Suítes de teste automatizado.' },
    ],
    testingStrategy: 'Testes unitários cobrindo todas as permutações de equivalência e bloqueio de vencedor.',
    acceptanceCriteria: {
      minLinesPct: 95,
      minFunctionsPct: 95,
      minBranchesPct: 95,
      minStatementsPct: 95,
      tier: 'CRITICAL_MOTOR',
    },
  },
  {
    id: 'src/gate/',
    name: 'Motor Determinístico de Quality Gates',
    responsibility:
      'Avaliação de Quality Gates com condições obrigatórias, opcionais e informativas, códigos de saída CLI e webhooks assinados.',
    directories: ['src/gate'],
    eligibleExtensions: ['.ts'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Suítes de teste automatizado.' },
    ],
    testingStrategy: 'Testes de decisão determinística, tratamento de NOT_MEASURED e proteção SSRF em webhooks.',
    acceptanceCriteria: {
      minLinesPct: 85,
      minFunctionsPct: 85,
      minBranchesPct: 80,
      minStatementsPct: 85,
      tier: 'CORE_SECURITY_ENGINE',
    },
  },
  {
    id: 'src/security/',
    name: 'Segurança da Plataforma, Keystore Envelope e Autenticação',
    responsibility:
      'Gerenciamento de chaves por envelope (DEK AES-256-GCM + KEK DPAPI/OS/HKDF), autenticação (Argon2id/Scrypt), TOTP anti-replay, WebAuthn/FIDO2, RBAC e CSRF.',
    directories: ['src/security'],
    eligibleExtensions: ['.ts'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Suítes de teste automatizado.' },
    ],
    testingStrategy: 'Testes de segurança de cofre, migração de senhas, bloqueio de replay TOTP, CSRF e RBAC.',
    acceptanceCriteria: {
      minLinesPct: 80,
      minFunctionsPct: 80,
      minBranchesPct: 75,
      minStatementsPct: 80,
      tier: 'CORE_SECURITY_ENGINE',
    },
  },
  {
    id: 'src/execution/',
    name: 'Execução Isolada (Sandbox), Proteção SSRF e Cobertura',
    responsibility:
      'Execução controlada em sandbox, guarda anti-SSRF com revalidação de redirecionamentos, runner de testes/performance e parser de cobertura.',
    directories: ['src/execution'],
    eligibleExtensions: ['.ts'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Suítes de teste automatizado.' },
    ],
    testingStrategy: 'Testes de bloqueio de IPs privados/loopback/metadata, isolamento de subprocessos e parsers LCOV/JaCoCo/Cobertura/Istanbul.',
    acceptanceCriteria: {
      minLinesPct: 80,
      minFunctionsPct: 80,
      minBranchesPct: 75,
      minStatementsPct: 80,
      tier: 'CORE_SECURITY_ENGINE',
    },
  },
  {
    id: 'src/integrations/',
    name: 'Integrações MqrBridge, Scanners e Conectores Externos',
    responsibility:
      'Mapeamento de métricas externas, Quality Gates remotos, paginação de issues e gerenciador de scanners.',
    directories: ['src/integrations'],
    eligibleExtensions: ['.ts'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Suítes de teste automatizado.' },
      { pattern: '**/types.ts', justification: 'Declarações puras de interfaces TypeScript.' },
    ],
    testingStrategy: 'Testes de integração com servidores HTTP locais simulando paginação, falhas parciais e mapeamento sem inflação de nota.',
    acceptanceCriteria: {
      minLinesPct: 80,
      minFunctionsPct: 80,
      minBranchesPct: 75,
      minStatementsPct: 80,
      tier: 'INTEGRATION_AND_UI',
    },
  },
  {
    id: 'src/reports/',
    name: 'Exportador de Relatórios e Gerador PDF/HTML/JSON/SARIF',
    responsibility:
      'Geração de laudos técnicos preservando proveniência de métricas, limitações de escopo e cadeia de assinatura.',
    directories: ['src/reports'],
    eligibleExtensions: ['.ts'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Suítes de teste automatizado.' },
    ],
    testingStrategy: 'Testes de integridade de relatórios exportados, cabeçalhos PDF e conformidade SARIF 2.1.0.',
    acceptanceCriteria: {
      minLinesPct: 85,
      minFunctionsPct: 85,
      minBranchesPct: 80,
      minStatementsPct: 85,
      tier: 'CORE_SECURITY_ENGINE',
    },
  },
  {
    id: 'src/components/',
    name: 'Interface Técnica React/TSX e Componentes de Visualização',
    responsibility:
      'Módulos visuais do console de auditoria, filtros avançados, modais de autenticação, barra de jornada e painéis de governança.',
    directories: ['src/components'],
    eligibleExtensions: ['.ts', '.tsx'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Suítes de teste automatizado.' },
      { pattern: '**/*.test.tsx', justification: 'Suítes de teste automatizado de interface.' },
    ],
    testingStrategy: 'Testes automatizados de renderização SSR/estrutural, ciclo de vida de componentes e verificação E2E Playwright.',
    acceptanceCriteria: {
      minLinesPct: 70,
      minFunctionsPct: 70,
      minBranchesPct: 65,
      minStatementsPct: 70,
      tier: 'INTEGRATION_AND_UI',
    },
  },
  {
    id: 'src/desktop/',
    name: 'Arquitetura Desktop Electron e Ciclo de Vida Windows/Linux',
    responsibility:
      'Inicialização sequencial do servidor embarcado, isolamento de diretórios do usuário e validação de canais IPC.',
    directories: ['src/desktop', 'src/storage'],
    eligibleExtensions: ['.ts'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Suítes de teste automatizado.' },
    ],
    testingStrategy: 'Testes de inicialização headless, fallback de porta ocupada, bloqueio de Program Files e preload bridge.',
    acceptanceCriteria: {
      minLinesPct: 80,
      minFunctionsPct: 80,
      minBranchesPct: 75,
      minStatementsPct: 80,
      tier: 'INTEGRATION_AND_UI',
    },
  },
  {
    id: 'packages/vscode-extension/',
    name: 'Extensão Oficial WinHood para VS Code',
    responsibility:
      'Auditoria inline na IDE, diagnósticos SARIF e verificação de Quality Gate local.',
    directories: ['packages/vscode-extension/src'],
    eligibleExtensions: ['.ts'],
    excludedPatterns: [
      { pattern: '**/*.test.ts', justification: 'Suítes de teste de integração da extensão.' },
    ],
    testingStrategy: 'Testes de integração exercitando comandos de auditoria, diagnósticos e status bar.',
    acceptanceCriteria: {
      minLinesPct: 80,
      minFunctionsPct: 80,
      minBranchesPct: 75,
      minStatementsPct: 80,
      tier: 'INTEGRATION_AND_UI',
    },
  },
];

export function scanOfficial13DomainsInventory(rootDir = process.cwd()): DomainInventoryFileScan[] {
  return OFFICIAL_13_COVERAGE_DOMAINS.map((descriptor) => {
    const eligibleFiles: string[] = [];
    const excludedFiles: Array<{ filePath: string; reason: string }> = [];

    const walk = (absDir: string) => {
      if (!fs.existsSync(absDir)) return;
      for (const entry of fs.readdirSync(absDir, { withFileTypes: true })) {
        const full = path.join(absDir, entry.name);
        const rel = path.relative(rootDir, full).replace(/\\/g, '/');
        if (entry.isDirectory()) {
          walk(full);
          continue;
        }
        const ext = path.extname(entry.name);
        if (!descriptor.eligibleExtensions.includes(ext)) {
          continue;
        }
        if (entry.name.endsWith('.test.ts') || entry.name.endsWith('.test.tsx') || entry.name.endsWith('.d.ts')) {
          excludedFiles.push({
            filePath: rel,
            reason: 'Arquivo de teste automatizado ou declaração estática .d.ts.',
          });
          continue;
        }
        if (entry.name === 'types.ts') {
          excludedFiles.push({
            filePath: rel,
            reason: 'Arquivo exclusivo de contratos e interfaces TypeScript sem código executável em runtime.',
          });
          continue;
        }
        eligibleFiles.push(rel);
      }
    };

    for (const relDir of descriptor.directories) {
      walk(path.join(rootDir, relDir));
    }

    eligibleFiles.sort((a, b) => a.localeCompare(b));
    excludedFiles.sort((a, b) => a.filePath.localeCompare(b.filePath));

    return {
      domainId: descriptor.id,
      descriptor,
      eligibleFiles,
      excludedFiles,
    };
  });
}

export function computeThreeWaySeparatedCoverage(params: {
  testCoverage?: Partial<SeparatedTestCoverageMetric> | null;
  discoveredFilesCount: number;
  eligibleFilesCount: number;
  ingestedFilesCount: number;
  excludedFilesCount?: number;
  failedIngestionFilesCount?: number;
  analyzedFilesCount: number;
  fullAstFilesCount?: number;
  structuralAstFilesCount?: number;
  partialRecoveryFilesCount?: number;
  failedParseFilesCount?: number;
  unsupportedFilesCount?: number;
}): ThreeWaySeparatedCoverageBundle {
  const {
    testCoverage,
    discoveredFilesCount,
    eligibleFilesCount,
    ingestedFilesCount,
    excludedFilesCount = Math.max(0, discoveredFilesCount - eligibleFilesCount),
    failedIngestionFilesCount = 0,
    analyzedFilesCount,
    fullAstFilesCount = analyzedFilesCount,
    structuralAstFilesCount = 0,
    partialRecoveryFilesCount = 0,
    failedParseFilesCount = 0,
    unsupportedFilesCount = 0,
  } = params;

  const ingestionPct =
    eligibleFilesCount > 0
      ? Math.min(100, Math.round((ingestedFilesCount / eligibleFilesCount) * 1000) / 10)
      : null;

  const analysisPct =
    eligibleFilesCount > 0
      ? Math.min(100, Math.round((analyzedFilesCount / eligibleFilesCount) * 1000) / 10)
      : null;

  const fullAstRatioPct =
    analyzedFilesCount > 0
      ? Math.min(100, Math.round((fullAstFilesCount / analyzedFilesCount) * 1000) / 10)
      : null;

  const ingestionStatus: SeparatedIngestionCoverageMetric['status'] =
    eligibleFilesCount === 0
      ? 'NOT_INGESTED'
      : failedIngestionFilesCount > 0 && ingestedFilesCount === 0
        ? 'FAILED'
        : ingestedFilesCount >= eligibleFilesCount
          ? 'COMPLETE'
          : 'PARTIAL';

  const analysisStatus: SeparatedAnalysisCoverageMetric['status'] =
    eligibleFilesCount === 0 || analyzedFilesCount === 0
      ? failedParseFilesCount > 0
        ? 'FAILED'
        : 'NOT_ANALYZED'
      : analyzedFilesCount >= eligibleFilesCount && failedParseFilesCount === 0 && partialRecoveryFilesCount === 0
        ? 'COMPLETE'
        : 'PARTIAL';

  return {
    separatedIndicatorsNote:
      'Indicadores estritamente independentes: (A) testCoverage mede execução em testes automatizados; (B) ingestionCoverage mede arquivos elegíveis recebidos/ingeridos; (C) analysisCoverage mede arquivos efetivamente interpretados pelo motor analítico.',
    testCoverage: {
      indicatorType: 'TEST_COVERAGE',
      methodology: 'V8_SOURCEMAP_CONVENTIONAL',
      sourceMapValidated: testCoverage?.sourceMapValidated ?? false,
      instrumentedFilesCount: testCoverage?.instrumentedFilesCount ?? 0,
      uninstrumentedFilesCount: testCoverage?.uninstrumentedFilesCount ?? eligibleFilesCount,
      uninstrumentedFiles: testCoverage?.uninstrumentedFiles ?? [],
      statements: testCoverage?.statements ?? { total: 0, covered: 0, pct: null },
      lines: testCoverage?.lines ?? { total: 0, covered: 0, pct: null },
      functions: testCoverage?.functions ?? { total: 0, covered: 0, pct: null },
      branches: testCoverage?.branches ?? { total: 0, covered: 0, pct: null },
    },
    ingestionCoverage: {
      indicatorType: 'INGESTION_COVERAGE',
      discoveredFilesCount,
      eligibleFilesCount,
      ingestedFilesCount,
      excludedFilesCount,
      failedIngestionFilesCount,
      ingestionCoveragePct: ingestionPct,
      status: ingestionStatus,
    },
    analysisCoverage: {
      indicatorType: 'ANALYSIS_COVERAGE',
      eligibleFilesCount,
      analyzedFilesCount,
      fullAstFilesCount,
      structuralAstFilesCount,
      partialRecoveryFilesCount,
      failedParseFilesCount,
      unsupportedFilesCount,
      analysisCoveragePct: analysisPct,
      fullAstRatioPct,
      status: analysisStatus,
    },
  };
}
