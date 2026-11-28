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

const DEFAULT_TEST_EXCLUSION = {
  pattern: '**/*.test.ts',
  justification: 'Suítes de teste automatizado.',
} as const;

function createCoverageDomain(
  id: CoverageDomainId,
  name: string,
  responsibility: string,
  testingStrategy: string,
  tier: CoverageDomainDescriptor['acceptanceCriteria']['tier'],
  overrides?: {
    directories?: string[];
    eligibleExtensions?: string[];
    excludedPatterns?: Array<{ pattern: string; justification: string }>;
    thresholds?: [number, number, number, number];
  }
): CoverageDomainDescriptor {
  const defaultThresholds: Record<
    CoverageDomainDescriptor['acceptanceCriteria']['tier'],
    [number, number, number, number]
  > = {
    CRITICAL_MOTOR: [95, 95, 95, 95],
    CORE_SECURITY_ENGINE: [80, 80, 75, 80],
    INTEGRATION_AND_UI: [80, 80, 75, 80],
  };
  const [minLinesPct, minFunctionsPct, minBranchesPct, minStatementsPct] =
    overrides?.thresholds ?? defaultThresholds[tier];
  const defaultDir = id.endsWith('/') ? id.slice(0, -1) : id;
  return {
    id,
    name,
    responsibility,
    directories: overrides?.directories ?? [defaultDir],
    eligibleExtensions: overrides?.eligibleExtensions ?? ['.ts'],
    excludedPatterns: overrides?.excludedPatterns ?? [{ ...DEFAULT_TEST_EXCLUSION }],
    testingStrategy,
    acceptanceCriteria: {
      minLinesPct,
      minFunctionsPct,
      minBranchesPct,
      minStatementsPct,
      tier,
    },
  };
}

export const OFFICIAL_13_COVERAGE_DOMAINS: readonly CoverageDomainDescriptor[] = [
  createCoverageDomain(
    'src/analyzers/',
    'Analisadores Estáticos, AST, Taint, Segredos e SCA/SBOM',
    'Parsing AST/estrutural multi-linguagem, análise de fluxo de dados (Taint), catálogo de regras SAST/MQR, detecção de segredos, correlação SCA e geração de SBOM.',
    'Testes unitários e de integração com casos positivos/negativos por linguagem, sanitizadores contextuais e SBOM.',
    'CORE_SECURITY_ENGINE',
    {
      excludedPatterns: [
        { pattern: '**/*.test.ts', justification: 'Arquivos de suíte de teste automatizado (não compõem o denominador de produção).' },
        { pattern: '**/types.ts', justification: 'Declarações puras de tipos TypeScript sem instruções executáveis em runtime.' },
      ],
    }
  ),
  createCoverageDomain(
    'src/engine/',
    'Orquestrador de Benchmark, Scoring Multidimensional e Proveniência',
    'Orquestração de execuções, cálculo determinístico das 12 dimensões, cadeia de evidências SHA-256 e catálogo metodológico.',
    'Testes determinísticos bit-a-bit, autoauditoria e validação de proveniência.',
    'CORE_SECURITY_ENGINE'
  ),
  createCoverageDomain(
    'src/scoring/',
    'Motor Crítico de Pontuação e Penalidades',
    'Agregação matemática ponderada, aplicação de Penalty Caps e classificação em escala 0.00–5.00.',
    'Testes unitários exaustivos de fronteira, pesos nulos, caps críticos e métricas ausentes.',
    'CRITICAL_MOTOR'
  ),
  createCoverageDomain(
    'src/evidence/',
    'Motor Crítico de Cadeia de Evidências e Assinaturas',
    'Geração e verificação de manifestos assinados (HMAC-SHA256 e Ed25519) e encadeamento criptográfico.',
    'Testes de integridade, detecção de adulteração, rotação de chaves e Trust Store Ed25519.',
    'CRITICAL_MOTOR'
  ),
  createCoverageDomain(
    'src/comparability/',
    'Motor Crítico de Comparabilidade A/B Bimodal',
    'Validação de equivalência intraclasse (mesmo motor) e interferramentas (ferramentas distintas) nos estados STRICTLY_COMPARABLE, QUALIFIED_COMPARISON e NOT_COMPARABLE.',
    'Testes unitários cobrindo todas as permutações de equivalência e bloqueio de vencedor.',
    'CRITICAL_MOTOR'
  ),
  createCoverageDomain(
    'src/gate/',
    'Motor Determinístico de Quality Gates',
    'Avaliação de Quality Gates com condições obrigatórias, opcionais e informativas, códigos de saída CLI e webhooks assinados.',
    'Testes de decisão determinística, tratamento de NOT_MEASURED e proteção SSRF em webhooks.',
    'CORE_SECURITY_ENGINE',
    { thresholds: [85, 85, 80, 85] }
  ),
  createCoverageDomain(
    'src/security/',
    'Segurança da Plataforma, Keystore Envelope e Autenticação',
    'Gerenciamento de chaves por envelope (DEK AES-256-GCM + KEK DPAPI/OS/HKDF), autenticação (Argon2id/Scrypt), TOTP anti-replay, WebAuthn/FIDO2, RBAC e CSRF.',
    'Testes de segurança de cofre, migração de senhas, bloqueio de replay TOTP, CSRF e RBAC.',
    'CORE_SECURITY_ENGINE'
  ),
  createCoverageDomain(
    'src/execution/',
    'Execução Isolada (Sandbox), Proteção SSRF e Cobertura',
    'Execução controlada em sandbox, guarda anti-SSRF com revalidação de redirecionamentos, runner de testes/performance e parser de cobertura.',
    'Testes de bloqueio de IPs privados/loopback/metadata, isolamento de subprocessos e parsers LCOV/JaCoCo/Cobertura/Istanbul.',
    'CORE_SECURITY_ENGINE'
  ),
  createCoverageDomain(
    'src/integrations/',
    'Integrações MqrBridge, Scanners e Conectores Externos',
    'Mapeamento de métricas externas, Quality Gates remotos, paginação de issues e gerenciador de scanners.',
    'Testes de integração com servidores HTTP locais simulando paginação, falhas parciais e mapeamento sem inflação de nota.',
    'INTEGRATION_AND_UI',
    {
      excludedPatterns: [
        { ...DEFAULT_TEST_EXCLUSION },
        { pattern: '**/types.ts', justification: 'Declarações puras de interfaces TypeScript.' },
      ],
    }
  ),
  createCoverageDomain(
    'src/reports/',
    'Exportador de Relatórios e Gerador PDF/HTML/JSON/SARIF',
    'Geração de laudos técnicos preservando proveniência de métricas, limitações de escopo e cadeia de assinatura.',
    'Testes de integridade de relatórios exportados, cabeçalhos PDF e conformidade SARIF 2.1.0.',
    'CORE_SECURITY_ENGINE',
    { thresholds: [85, 85, 80, 85] }
  ),
  createCoverageDomain(
    'src/components/',
    'Interface Técnica React/TSX e Componentes de Visualização',
    'Módulos visuais do console de auditoria, filtros avançados, modais de autenticação, barra de jornada e painéis de governança.',
    'Testes automatizados de renderização SSR/estrutural, ciclo de vida de componentes e verificação E2E Playwright.',
    'INTEGRATION_AND_UI',
    {
      eligibleExtensions: ['.ts', '.tsx'],
      excludedPatterns: [
        { ...DEFAULT_TEST_EXCLUSION },
        { pattern: '**/*.test.tsx', justification: 'Suítes de teste automatizado de interface.' },
      ],
      thresholds: [70, 70, 65, 70],
    }
  ),
  createCoverageDomain(
    'src/desktop/',
    'Arquitetura Desktop Electron e Ciclo de Vida Windows/Linux',
    'Inicialização sequencial do servidor embarcado, isolamento de diretórios do usuário e validação de canais IPC.',
    'Testes de inicialização headless, fallback de porta ocupada, bloqueio de Program Files e preload bridge.',
    'INTEGRATION_AND_UI',
    { directories: ['src/desktop', 'src/storage'] }
  ),
  createCoverageDomain(
    'packages/vscode-extension/',
    'Extensão Oficial WinHood para VS Code',
    'Auditoria inline na IDE, diagnósticos SARIF e verificação de Quality Gate local.',
    'Testes de integração exercitando comandos de auditoria, diagnósticos e status bar.',
    'INTEGRATION_AND_UI',
    {
      directories: ['packages/vscode-extension/src'],
      excludedPatterns: [
        { pattern: '**/*.test.ts', justification: 'Suítes de teste de integração da extensão.' },
      ],
    }
  ),
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
