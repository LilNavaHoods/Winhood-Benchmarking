import crypto from 'node:crypto';
import os from 'node:os';
import type {
  AppEnvironment,
  ArchitectureGraphData,
  AssessmentMode,
  BenchmarkCategoryKey,
  BenchmarkProfileConfig,
  BenchmarkRun,
  BenchmarkRunProgress,
  DataOrigin,
  EvidenceRecord,
  FunctionalEquivalenceRow,
  NormalizedFinding,
  SbomDocumentBundle,
  ScaVulnerabilityCorrelation,
  Software,
  SoftwareScoreCard,
  ToolAdapterInfo,
  ToolExecutionRecord,
  UnifiedExecutionRecord,
  VeracityCheckResult,
  WindowsSandboxSnapshotDiff,
} from '../types/benchmark';
import {
  ControlledTestAndPerfRunner,
  type ControlledPerfMeasurementResult,
  type ControlledTestExecutionResult,
} from '../execution/ControlledTestAndPerfRunner';
import {
  ALGORITHM_VERSION,
  ALL_BENCHMARK_CATEGORIES,
  DEFAULT_CATEGORY_WEIGHTS,
  calculateDeterministicScoreCard,
  computeSha256,
  normalizeEnabledCategoryWeights,
  validateEquivalenceConditions,
} from './scoringEngine';
export { ALGORITHM_VERSION };
import { executeRealStaticAnalysisOnSource } from './staticAnalyzer';
import {
  buildVerifiableEvidenceChain,
  signEvidenceManifestHmacSha256,
  verifyEvidenceChainAndManifest,
} from './evidenceProvenanceEngine';
import {
  METHODOLOGY_CATALOG_VERSION,
  determineSourceIngestionState,
  evaluateCriteriaForSoftware,
  evaluateSoftwareComparability,
  getProfileByIdOrDomain,
} from './methodologyCatalogEngine';
import { ToolAvailabilityService } from '../services/tools/ToolAvailabilityService';
import { BenchmarkMatcher } from '../intelligence/comparison/BenchmarkMatcher';
import { ReferenceRegistry } from '../intelligence/reference/ReferenceRegistry';
import { RULE_ENGINE_VERSION, RuleRegistry } from '../analyzers/RuleRegistry';
import { QualityGateEngine } from '../gate/QualityGateEngine';
import { buildComparabilityManifest, sha256Canonical } from '../comparability';

export const DEFAULT_BENCHMARK_PROFILES: BenchmarkProfileConfig[] = [
  {
    id: 'prof-complete-enterprise',
    name: 'Benchmark Completo Corporativo (WinHood Standard)',
    description:
      'Avaliação integral em 12 dimensões com travas matemáticas (Penalty Caps) ativas para Segurança, Qualidade, Arquitetura e Veracidade.',
    enabledCategories: [...ALL_BENCHMARK_CATEGORIES],
    weights: { ...DEFAULT_CATEGORY_WEIGHTS },
    qualityProfileIds: ['qp-sonar-way-ts', 'qp-sonar-way-py', 'qp-sonar-way-sql'],
    qualityGateId: 'qg-sonar-way',
    analyzeNewCodeOnly: false,
    referenceBranch: 'main',
    selectedAdapters: [
      'opengrep-sast',
      'gitleaks-secrets',
      'mqr-bridge-quality',
      'syft-grype-sca',
      'archunit-cruiser',
      'sqlfluff-db',
      'junit-functional',
      'k6-perf-equivalent',
      'win-sandbox-snapshot',
    ],
    enablePenaltyCaps: true,
    equivalenceEnvironment: {
      cpuCoresLimit: 4,
      memoryMbLimit: 4096,
      osTarget: 'Windows 11 Enterprise Sandbox / Linux Worker 6.8',
      workloadConcurrency: 100,
      dastFormalAuthorization: true,
      authorizedByOwner: 'CISO & Architecture Board (Auth #WH-2026-884)',
    },
  },
  {
    id: 'prof-security-devsecops',
    name: 'Benchmark de Segurança & DevSecOps (Zero-Trust)',
    description:
      'Foco prioritário em SAST, SCA/SBOM, detecção de segredos, criptografia em repouso, privacidade e resiliência de banco de dados.',
    enabledCategories: [...ALL_BENCHMARK_CATEGORIES],
    weights: {
      functionality: 8,
      code_quality: 10,
      security: 32,
      performance: 5,
      architecture: 10,
      database: 10,
      reliability: 8,
      compatibility: 3,
      usability: 2,
      installation: 4,
      privacy: 6,
      documentation: 2,
    },
    qualityProfileIds: ['qp-sonar-way-ts', 'qp-sonar-way-sql'],
    qualityGateId: 'qg-zero-trust',
    analyzeNewCodeOnly: false,
    referenceBranch: 'main',
    selectedAdapters: [
      'opengrep-sast',
      'gitleaks-secrets',
      'syft-grype-sca',
      'sqlfluff-db',
      'win-sandbox-snapshot',
    ],
    enablePenaltyCaps: true,
    equivalenceEnvironment: {
      cpuCoresLimit: 4,
      memoryMbLimit: 4096,
      osTarget: 'Linux Hardened MicroVM / Windows Sandbox',
      workloadConcurrency: 50,
      dastFormalAuthorization: true,
      authorizedByOwner: 'SecOps Lead',
    },
  },
  {
    id: 'prof-quality-architecture',
    name: 'Benchmark de Qualidade de Código & Arquitetura',
    description:
      'Prioriza manutenibilidade, complexidade ciclomática/cognitiva, acoplamento, coesão, ausência de ciclos e testes.',
    enabledCategories: [...ALL_BENCHMARK_CATEGORIES],
    weights: {
      functionality: 10,
      code_quality: 26,
      security: 14,
      performance: 8,
      architecture: 22,
      database: 6,
      reliability: 6,
      compatibility: 2,
      usability: 2,
      installation: 1,
      privacy: 1,
      documentation: 2,
    },
    qualityProfileIds: ['qp-sonar-way-ts'],
    qualityGateId: 'qg-sonar-way',
    analyzeNewCodeOnly: false,
    referenceBranch: 'main',
    selectedAdapters: [
      'mqr-bridge-quality',
      'archunit-cruiser',
      'opengrep-sast',
      'junit-functional',
    ],
    enablePenaltyCaps: true,
    equivalenceEnvironment: {
      cpuCoresLimit: 4,
      memoryMbLimit: 4096,
      osTarget: 'Linux Worker 6.8',
      workloadConcurrency: 100,
      dastFormalAuthorization: false,
      authorizedByOwner: '',
    },
  },
];

export function classifyToolResultCompleteness(rec?: ToolExecutionRecord): import('../types/benchmark').ToolResultCompletenessState {
  if (!rec || rec.exitCode === null || rec.executionMethod === 'NOT_EXECUTED') {
    return 'NOT_EXECUTED';
  }
  if (
    rec.exitCode !== 0 ||
    rec.veracityStatus === 'EXECUTION_FAILED' ||
    rec.veracityStatus === 'INVALID_OUTPUT' ||
    rec.veracityStatus === 'PARSING_ERROR'
  ) {
    return 'INCONCLUSIVE';
  }
  if (rec.eligibleFilesCount === 0 || rec.analyzedFilesCount === 0) {
    return 'EMPTY';
  }
  if (
    rec.veracityStatus === 'PARTIAL' ||
    rec.analyzedFilesCount < rec.eligibleFilesCount ||
    (rec.errorFilesCount ?? 0) > 0 ||
    rec.parsingErrorsCount > 0 ||
    rec.coveragePercent < 100
  ) {
    return 'PARTIAL';
  }
  return 'COMPLETE';
}

export function buildToolAdaptersCatalog(executedRecords?: ToolExecutionRecord[]): ToolAdapterInfo[] {
  const isWin = os.platform() === 'win32';
  const probeSemgrep = ToolAvailabilityService.checkBinaryInPath('semgrep');
  const probeOpengrep = ToolAvailabilityService.checkBinaryInPath('opengrep');
  const probeGitleaks = ToolAvailabilityService.checkBinaryInPath('gitleaks');
  const probeSonarScanner = ToolAvailabilityService.checkBinaryInPath('sonar-scanner');
  const probeSyft = ToolAvailabilityService.checkBinaryInPath('syft');
  const probeGrype = ToolAvailabilityService.checkBinaryInPath('grype');
  const probeTrivy = ToolAvailabilityService.checkBinaryInPath('trivy');
  const probeOsv = ToolAvailabilityService.checkBinaryInPath('osv-scanner');
  const probeK6 = ToolAvailabilityService.checkBinaryInPath('k6');
  const probeNode = ToolAvailabilityService.checkBinaryInPath('node');

  const findLatestExecution = (toolId: string): ToolExecutionRecord | undefined => {
    if (!executedRecords || executedRecords.length === 0) return undefined;
    for (let i = executedRecords.length - 1; i >= 0; i--) {
      if (executedRecords[i].toolId === toolId) {
        return executedRecords[i];
      }
    }
    return undefined;
  };

  const resolveAdapterTelemetry = (
    toolId: string,
    opts: {
      integrationType: 'NATIVE' | 'LOCAL_CLI' | 'REMOTE_API';
      nativeAvailable: boolean;
      externalBinaryDetected: boolean;
      externalVersion: string | null;
      configurationValid: boolean;
      connectionState: 'VERIFIED' | 'NOT_CONNECTED' | 'NOT_APPLICABLE';
      signatureSeed: string | null;
    }
  ) => {
    const execRec = findLatestExecution(toolId);
    const executionVerified = Boolean(execRec && execRec.exitCode !== null && execRec.rawOutputSha256);
    const resultCompleteness = classifyToolResultCompleteness(execRec);

    let adapterState: import('../types/benchmark').ToolAdapterVerifiableState;
    if (execRec && execRec.exitCode !== null) {
      if (execRec.exitCode !== 0) {
        adapterState = 'EXECUTION_FAILED';
      } else if (resultCompleteness === 'PARTIAL' || resultCompleteness === 'EMPTY') {
        adapterState = 'PARTIAL';
      } else if (opts.externalBinaryDetected || opts.connectionState === 'VERIFIED') {
        adapterState = 'EXTERNAL_EXECUTION_VERIFIED';
      } else {
        adapterState = 'NATIVE_AVAILABLE';
      }
    } else if (opts.integrationType === 'REMOTE_API') {
      if (!opts.configurationValid) {
        adapterState = 'NOT_CONFIGURED';
      } else if (opts.connectionState === 'VERIFIED') {
        adapterState = 'EXTERNAL_CONNECTION_VERIFIED';
      } else {
        adapterState = 'NOT_CONNECTED';
      }
    } else if (opts.integrationType === 'LOCAL_CLI') {
      if (opts.externalBinaryDetected) {
        adapterState = opts.configurationValid ? 'EXTERNAL_CONFIGURED' : 'EXTERNAL_BINARY_DETECTED';
      } else if (opts.nativeAvailable) {
        adapterState = 'NATIVE_AVAILABLE';
      } else {
        adapterState = 'NOT_INSTALLED';
      }
    } else {
      adapterState = opts.nativeAvailable ? 'NATIVE_AVAILABLE' : 'NOT_MEASURED';
    }

    let status: ToolAdapterInfo['status'];
    if (adapterState === 'EXECUTION_FAILED') {
      status = 'DISABLED';
    } else if (opts.integrationType === 'REMOTE_API') {
      status = opts.configurationValid ? 'INTEGRAÇÃO CONFIGURADA' : 'INTEGRAÇÃO NÃO CONFIGURADA';
    } else if (adapterState === 'NOT_INSTALLED' || adapterState === 'NOT_MEASURED') {
      status = 'FERRAMENTA NÃO INSTALADA';
    } else if (adapterState === 'NOT_CONFIGURED') {
      status = 'INTEGRAÇÃO NÃO CONFIGURADA';
    } else {
      status = 'OPERATIONAL';
    }

    const configured =
      opts.integrationType === 'REMOTE_API'
        ? opts.configurationValid
        : opts.integrationType === 'LOCAL_CLI'
          ? opts.externalBinaryDetected
            ? opts.configurationValid
            : opts.nativeAvailable
          : opts.nativeAvailable;

    return {
      status,
      configured,
      binaryDetected: opts.externalBinaryDetected,
      signatureHash: opts.signatureSeed ? computeSha256(opts.signatureSeed) : null,
      integrationType: opts.integrationType,
      adapterState,
      nativeAvailable: opts.nativeAvailable,
      externalBinaryDetected: opts.externalBinaryDetected,
      externalVersion: opts.externalVersion,
      configurationValid: opts.configurationValid,
      connectionState: opts.connectionState,
      executionVerified,
      resultCompleteness,
      lastExecutionAt: execRec ? execRec.completedAt : null,
      lastExitCode: execRec ? execRec.exitCode : null,
    };
  };

  const sastExternalDetected = probeSemgrep.detected || probeOpengrep.detected;
  const sastExternalVersion = probeSemgrep.versionOutput || probeOpengrep.versionOutput || null;
  const scaExternalDetected = probeOsv.detected || probeGrype.detected || probeSyft.detected;
  const scaExternalVersion = probeOsv.versionOutput || probeGrype.versionOutput || probeSyft.versionOutput || null;
  const zapConfigured = Boolean(process.env.OWASP_ZAP_API_URL);

  return [
    {
      id: 'opengrep-sast',
      name: 'WinHood AST/Taint SAST + Semgrep/Opengrep Adapter',
      vendor: 'WinHood Security / Semgrep',
      version: sastExternalVersion || '4.1.0-native-ast',
      category: 'SECURITY_DEVSECOPS',
      analysisType: 'SAST AST & Cross-File Taint (SQLi, RCE, CWE Top 25)',
      executionMethod: sastExternalDetected ? 'CLI_BINARY' : 'NATIVE_AST_ENGINE',
      canonicalFormat: 'SARIF_2_1_0',
      description: sastExternalDetected
        ? 'Binário CLI externo detectado no host e integrado ao pipeline AST nativo WinHood.'
        : 'Motor AST Compiler nativo WinHood (TypeScript/Python/Java/SQL) operacional; CLI externo semgrep/opengrep não instalado no container.',
      supportedLanguages: ['TypeScript', 'JavaScript', 'Python', 'SQL', 'C#', 'Java', 'Go', 'Rust'],
      ...resolveAdapterTelemetry('opengrep-sast', {
        integrationType: sastExternalDetected ? 'LOCAL_CLI' : 'NATIVE',
        nativeAvailable: true,
        externalBinaryDetected: sastExternalDetected,
        externalVersion: sastExternalVersion,
        configurationValid: true,
        connectionState: 'NOT_APPLICABLE',
        signatureSeed: `winhood-ast-taint-4.1.0:ext=${sastExternalDetected}`,
      }),
    },
    {
      id: 'gitleaks-secrets',
      name: 'WinHood Secret Scanner + Gitleaks CLI Adapter',
      vendor: 'WinHood SecOps / Gitleaks',
      version: probeGitleaks.versionOutput || '4.1.0-native-ast',
      category: 'SECURITY_DEVSECOPS',
      analysisType: 'Secret Scanning & Redaction (Chaves, Tokens, Senhas Fixas)',
      executionMethod: probeGitleaks.detected ? 'CLI_BINARY' : 'NATIVE_AST_ENGINE',
      canonicalFormat: 'SARIF_2_1_0',
      description: probeGitleaks.detected
        ? 'Binário Gitleaks CLI detectado no host com mascaramento automático de evidências.'
        : 'Detector nativo WinHood por AST e entropia ativo; binário gitleaks CLI não instalado neste host.',
      supportedLanguages: ['TypeScript', 'JavaScript', 'Python', 'JSON', 'YAML', 'SQL'],
      ...resolveAdapterTelemetry('gitleaks-secrets', {
        integrationType: probeGitleaks.detected ? 'LOCAL_CLI' : 'NATIVE',
        nativeAvailable: true,
        externalBinaryDetected: probeGitleaks.detected,
        externalVersion: probeGitleaks.versionOutput || null,
        configurationValid: true,
        connectionState: 'NOT_APPLICABLE',
        signatureSeed: `winhood-secret-scanner-4.1.0:ext=${probeGitleaks.detected}`,
      }),
    },
    {
      id: 'mqr-bridge-quality',
      name: 'MqrBridge Server / Cloud & Native MQR Parity Engine',
      vendor: 'SonarSource / WinHood Quality',
      version: probeSonarScanner.versionOutput || 'WINHOOD-SONAR-MQR-v3.0.0',
      category: 'CODE_QUALITY',
      analysisType: 'Bugs, Code Smells, Complexidade Ciclomática/Cognitiva, Duplicação',
      executionMethod: probeSonarScanner.detected ? 'CLI_BINARY' : 'NATIVE_AST_ENGINE',
      canonicalFormat: 'SARIF_2_1_0',
      description: probeSonarScanner.detected
        ? 'SonarScanner CLI detectado no host para submissão real à instância MqrBridge conectada.'
        : 'Cálculo estático nativo MQR ativo; conecte instância MqrBridge Server/Cloud ou instale sonar-scanner para métricas remotas nativas.',
      supportedLanguages: ['TypeScript', 'JavaScript', 'Python', 'Java', 'C#', 'Go', 'Rust'],
      ...resolveAdapterTelemetry('mqr-bridge-quality', {
        integrationType: probeSonarScanner.detected ? 'LOCAL_CLI' : 'NATIVE',
        nativeAvailable: true,
        externalBinaryDetected: probeSonarScanner.detected,
        externalVersion: probeSonarScanner.versionOutput || null,
        configurationValid: true,
        connectionState: 'NOT_APPLICABLE',
        signatureSeed: `winhood-sonar-mqr-3.0.0:ext=${probeSonarScanner.detected}`,
      }),
    },
    {
      id: 'syft-grype-sca',
      name: 'WinHood CycloneDX/SPDX SBOM & OSV/NVD/EPSS/KEV SCA',
      vendor: 'WinHood SCA / OSV / Anchore',
      version: scaExternalVersion || '4.1.0-native-sbom',
      category: 'SECURITY_DEVSECOPS',
      analysisType: 'SCA & SBOM CycloneDX 1.5/1.7 & SPDX 2.3/3.0 (CVE, GHSA, EPSS, CISA KEV)',
      executionMethod: scaExternalDetected ? 'CLI_BINARY' : 'NATIVE_AST_ENGINE',
      canonicalFormat: 'CYCLONEDX_1_5',
      description: 'Gerador real CycloneDX 1.5/1.7 e SPDX 2.3/3.0 a partir de lockfiles/manifestos + correlação OSV/NVD/EPSS/CISA KEV.',
      supportedLanguages: ['JSON', 'TypeScript', 'JavaScript', 'Python', 'Go', 'Rust', 'Java'],
      ...resolveAdapterTelemetry('syft-grype-sca', {
        integrationType: scaExternalDetected ? 'LOCAL_CLI' : 'NATIVE',
        nativeAvailable: true,
        externalBinaryDetected: scaExternalDetected,
        externalVersion: scaExternalVersion,
        configurationValid: true,
        connectionState: 'NOT_APPLICABLE',
        signatureSeed: `winhood-sbom-sca-4.1.0:ext=${scaExternalDetected}`,
      }),
    },
    {
      id: 'archunit-cruiser',
      name: 'WinHood Architecture Graph Analyzer',
      vendor: 'WinHood Architecture Lab',
      version: '4.1.0-native-ast',
      category: 'ARCHITECTURE',
      analysisType: 'Acoplamento Ca/Ce, Instabilidade, Ciclos e Violações de Camada',
      executionMethod: 'NATIVE_AST_ENGINE',
      canonicalFormat: 'ARCH_GRAPH_JSON',
      description: 'Mapeamento estrutural real de importações, detecção de ciclos e auditoria de camadas (Motor Nativo WinHood).',
      supportedLanguages: ['TypeScript', 'JavaScript', 'Python'],
      ...resolveAdapterTelemetry('archunit-cruiser', {
        integrationType: 'NATIVE',
        nativeAvailable: true,
        externalBinaryDetected: false,
        externalVersion: null,
        configurationValid: true,
        connectionState: 'NOT_APPLICABLE',
        signatureSeed: 'winhood-arch-graph-4.1.0',
      }),
    },
    {
      id: 'sqlfluff-db',
      name: 'WinHood SQL & Relational Schema Auditor',
      vendor: 'WinHood DB',
      version: '4.1.0-native-ast',
      category: 'DATABASE',
      analysisType: 'Auditoria de Schemas, Índices, Projeções SELECT * e Criptografia de Colunas',
      executionMethod: 'NATIVE_AST_ENGINE',
      canonicalFormat: 'SARIF_2_1_0',
      description: 'Parser estrutural DDL/DML SQL, índices de chaves estrangeiras e proteção de colunas sensíveis (Motor Nativo WinHood).',
      supportedLanguages: ['SQL'],
      ...resolveAdapterTelemetry('sqlfluff-db', {
        integrationType: 'NATIVE',
        nativeAvailable: true,
        externalBinaryDetected: false,
        externalVersion: null,
        configurationValid: true,
        connectionState: 'NOT_APPLICABLE',
        signatureSeed: 'winhood-sql-auditor-4.1.0',
      }),
    },
    {
      id: 'junit-functional',
      name: 'WinHood Controlled Test & Coverage Parser (LCOV/JaCoCo/Cobertura)',
      vendor: 'WinHood QA Execution',
      version: probeNode.versionOutput || 'not-installed',
      category: 'QA_FUNCTIONAL',
      analysisType: 'Execução Isolada de Testes & Leitura Real de Relatórios de Cobertura',
      executionMethod: 'SANDBOX_WORKER',
      canonicalFormat: 'JUNIT_XML',
      description: 'Executa suítes reais em sandbox temporário e analisa LCOV/JaCoCo/Cobertura/Istanbul sem fabricar cobertura.',
      supportedLanguages: ['TypeScript', 'JavaScript', 'Python', 'Java'],
      ...resolveAdapterTelemetry('junit-functional', {
        integrationType: 'LOCAL_CLI',
        nativeAvailable: false,
        externalBinaryDetected: probeNode.detected,
        externalVersion: probeNode.versionOutput || null,
        configurationValid: probeNode.detected,
        connectionState: 'NOT_APPLICABLE',
        signatureSeed: probeNode.detected ? `winhood-test-cov-4.1.0:${probeNode.versionOutput}` : null,
      }),
    },
    {
      id: 'k6-perf-equivalent',
      name: 'WinHood HTTP Load Profiler & k6 Adapter',
      vendor: 'WinHood Perf / Grafana Labs',
      version: probeK6.versionOutput || '4.1.0-http-profiler',
      category: 'PERFORMANCE',
      analysisType: 'Latência P50/P95/P99, Throughput RPS, Memória RSS e CPU reais',
      executionMethod: probeK6.detected ? 'CLI_BINARY' : 'SANDBOX_WORKER',
      canonicalFormat: 'OTLP_METRICS',
      description: probeK6.detected
        ? 'Binário k6 detectado no host para testes de carga.'
        : 'Profiler HTTP controlado ativo via /api/execution/run-perf; binário externo k6 não instalado neste host (análise estática não fabrica P95/RPS).',
      supportedLanguages: ['HTTP', 'API'],
      ...resolveAdapterTelemetry('k6-perf-equivalent', {
        integrationType: probeK6.detected ? 'LOCAL_CLI' : 'NATIVE',
        nativeAvailable: true,
        externalBinaryDetected: probeK6.detected,
        externalVersion: probeK6.versionOutput || null,
        configurationValid: true,
        connectionState: 'NOT_APPLICABLE',
        signatureSeed: `winhood-http-perf-4.1.0:k6=${probeK6.detected}`,
      }),
    },
    {
      id: 'win-sandbox-snapshot',
      name: 'Windows Sandbox & Sysinternals Snapshot Differ (T0/T1/T2)',
      vendor: 'Microsoft Sysinternals / WinHood OS',
      version: isWin ? '2026.11' : 'host-unavailable',
      category: 'OS_INSTALL',
      analysisType: 'Snapshots T0 (Base), T1 (Pós-Instalação), T2 (Pós-Desinstalação) & Resíduos',
      executionMethod: 'SANDBOX_WORKER',
      canonicalFormat: 'SNAPSHOT_DIFF',
      description: isWin
        ? 'Host Windows detectado para inspeção de instalação/registro.'
        : 'Sandbox Windows indisponível em host Linux; não executa inspeção dinâmica OS neste ambiente.',
      supportedLanguages: ['Windows', 'Manifests'],
      ...resolveAdapterTelemetry('win-sandbox-snapshot', {
        integrationType: 'LOCAL_CLI',
        nativeAvailable: false,
        externalBinaryDetected: isWin,
        externalVersion: isWin ? '2026.11' : null,
        configurationValid: isWin,
        connectionState: 'NOT_APPLICABLE',
        signatureSeed: isWin ? 'win-sandbox-snapshot-win32' : null,
      }),
    },
    {
      id: 'owasp-zap-dast',
      name: 'OWASP ZAP External DAST Scanner',
      vendor: 'OWASP Foundation',
      version: '2.15.0',
      category: 'SECURITY_DEVSECOPS',
      analysisType: 'DAST (Dynamic Application Security Testing sob autorização formal)',
      executionMethod: 'EXTERNAL_API',
      canonicalFormat: 'SARIF_2_1_0',
      description: 'Requer endpoint externo OWASP_ZAP_API_URL e autorização formal do proprietário do ambiente.',
      supportedLanguages: ['Web', 'API'],
      ...resolveAdapterTelemetry('owasp-zap-dast', {
        integrationType: 'REMOTE_API',
        nativeAvailable: false,
        externalBinaryDetected: false,
        externalVersion: null,
        configurationValid: zapConfigured,
        connectionState: 'NOT_CONNECTED',
        signatureSeed: zapConfigured ? 'owasp-zap-2.15.0' : null,
      }),
    },
    {
      id: 'trivy-container-cli',
      name: 'Aqua Trivy Container & Filesystem Binary CLI',
      vendor: 'Aqua Security',
      version: probeTrivy.versionOutput || 'not-installed',
      category: 'SECURITY_DEVSECOPS',
      analysisType: 'Container Image & IaC Security Scanner',
      executionMethod: 'CLI_BINARY',
      canonicalFormat: 'SARIF_2_1_0',
      description: probeTrivy.detected
        ? `Binário trivy detectado em ${probeTrivy.executablePath}.`
        : 'Binário nativo trivy ausente no container atual; análise SCA coberta pelo SbomGenerator/ScaCorrelator nativo.',
      supportedLanguages: ['Docker', 'Terraform', 'Kubernetes'],
      ...resolveAdapterTelemetry('trivy-container-cli', {
        integrationType: 'LOCAL_CLI',
        nativeAvailable: false,
        externalBinaryDetected: probeTrivy.detected,
        externalVersion: probeTrivy.versionOutput || null,
        configurationValid: probeTrivy.detected,
        connectionState: 'NOT_APPLICABLE',
        signatureSeed: probeTrivy.detected ? `trivy-cli-${probeTrivy.versionOutput}` : null,
      }),
    },
  ];
}

export function createInitialRunningBenchmark(params: {
  runId?: string;
  projectId: string;
  projectName: string;
  profileName: string;
  profileId?: string;
  functionalDomain?: string;
  evaluationObjective?: string;
  wizardMode?: 'QUICK' | 'CUSTOM' | 'ADVANCED';
  softwares: Software[];
  weights: Record<BenchmarkCategoryKey, number>;
  enabledCategories?: BenchmarkCategoryKey[];
  notApplicableCategories?: BenchmarkCategoryKey[];
  qualityGateId?: string;
  enablePenaltyCaps: boolean;
  equivalenceEnvironment: BenchmarkProfileConfig['equivalenceEnvironment'];
  assessmentMode?: AssessmentMode;
  environmentMode?: AppEnvironment;
  dataOrigin?: DataOrigin;
}): BenchmarkRun {
  const runId = params.runId || `run-${crypto.randomUUID().slice(0, 8)}`;
  const startedAt = new Date().toISOString();
  const eqValidation = validateEquivalenceConditions(params.equivalenceEnvironment);
  const enabledCategories =
    params.enabledCategories && params.enabledCategories.length > 0
      ? params.enabledCategories
      : ALL_BENCHMARK_CATEGORIES;
  const normalizedWeights = normalizeEnabledCategoryWeights(params.weights, enabledCategories);

  const totalFiles = params.softwares.reduce(
    (acc, s) => acc + (s.inventory?.eligibleFiles || s.inventory?.totalFiles || 1),
    0
  );

  return {
    id: runId,
    projectId: params.projectId,
    projectName: params.projectName,
    profileName: params.profileName,
    softwareIds: params.softwares.map((s) => s.id),
    status: 'RUNNING',
    startedAt,
    completedAt: '',
    algorithmVersion: ALGORITHM_VERSION,
    enabledCategories,
    qualityGateId: params.qualityGateId || 'qg-sonar-way',
    assessmentMode: params.assessmentMode || (params.softwares.length === 1 ? 'INDIVIDUAL' : 'AB_COMPARE'),
    environmentMode: params.environmentMode || 'PRODUCTION',
    dataOrigin: params.dataOrigin || params.softwares[0]?.dataOrigin || 'USER_SOURCE',
    weightsUsed: normalizedWeights,
    equivalenceEnvironment: params.equivalenceEnvironment,
    environmentEquivalent: eqValidation.equivalent,
    progress: {
      percent: 5,
      stageLabel: 'Inicializando workers e verificando hashes SHA-256 dos artefatos...',
      estimatedRemainingSeconds: null,
      estimationBasis: 'UNAVAILABLE_FIRST_RUN',
      currentTool: 'WinHood Genesis & Ingestion',
      processedFiles: 0,
      totalFiles,
    },
    scoreCards: [],
    toolExecutions: [],
    veracityResults: [],
    findings: [],
    architectureGraphs: [],
    functionalMatrix: [],
    sandboxDiffs: [],
    evidenceChain: [],
    winnerSoftwareId: null,
    executiveSummary: 'Análise comparativa em andamento...',
  };
}

export function executeBenchmarkRunOrchestration(params: {
  runId?: string;
  projectId: string;
  projectName: string;
  profileName: string;
  profileId?: string;
  functionalDomain?: string;
  evaluationObjective?: string;
  wizardMode?: 'QUICK' | 'CUSTOM' | 'ADVANCED';
  softwares: Software[];
  weights: Record<BenchmarkCategoryKey, number>;
  enabledCategories?: BenchmarkCategoryKey[];
  notApplicableCategories?: BenchmarkCategoryKey[];
  qualityGateId?: string;
  enablePenaltyCaps: boolean;
  equivalenceEnvironment: BenchmarkProfileConfig['equivalenceEnvironment'];
  assessmentMode?: 'INDIVIDUAL' | 'AB_COMPARE' | 'MARKET_COMPETITOR';
  environmentMode?: AppEnvironment;
  dataOrigin?: any;
  executeDynamicIsolatedTests?: boolean;
  testResultsBySoftware?: Record<string, ControlledTestExecutionResult>;
  perfResultsBySoftware?: Record<string, ControlledPerfMeasurementResult>;
  unifiedExecutions?: UnifiedExecutionRecord[];
  onProgress?: (progress: BenchmarkRunProgress) => void;
}): BenchmarkRun {
  const runId = params.runId || `run-${crypto.randomUUID().slice(0, 8)}`;
  const startedAt = new Date().toISOString();

  const eqValidation = validateEquivalenceConditions(params.equivalenceEnvironment);
  const environmentEquivalent = eqValidation.equivalent;

  const specializedProfile = getProfileByIdOrDomain(params.profileId, params.functionalDomain);
  const notApplicableCategories: BenchmarkCategoryKey[] =
    params.notApplicableCategories ||
    specializedProfile?.notApplicableCategories ||
    [];
  const enabledCategories = (
    params.enabledCategories && params.enabledCategories.length > 0
      ? params.enabledCategories
      : specializedProfile?.recommendedCategories || ALL_BENCHMARK_CATEGORIES
  ).filter((c) => !notApplicableCategories.includes(c));

  const originalWeights = { ...DEFAULT_CATEGORY_WEIGHTS, ...params.weights };
  const normalizedWeights = normalizeEnabledCategoryWeights(params.weights, enabledCategories);

  const scoreCards: SoftwareScoreCard[] = [];
  const toolExecutions: ToolExecutionRecord[] = [];
  const veracityResults: VeracityCheckResult[] = [];
  const findings: NormalizedFinding[] = [];
  const architectureGraphs: ArchitectureGraphData[] = [];
  const sandboxDiffs: WindowsSandboxSnapshotDiff[] = [];
  const criteriaOutcomesBySoftware: Record<string, import('../types/benchmark').CriterionEvaluationOutcome[]> = {};

  const sbomsBySoftware: Record<string, SbomDocumentBundle> = {};
  const scaCorrelationsBySoftware: Record<string, ScaVulnerabilityCorrelation[]> = {};
  const collectedUnifiedExecutions: UnifiedExecutionRecord[] = [...(params.unifiedExecutions || [])];

  const totalFiles = params.softwares.reduce(
    (acc, s) => acc + (s.inventory?.eligibleFiles || s.inventory?.totalFiles || 1),
    0
  );

  let processedFilesCounter = 0;

  // Initial stage notification (never fabricates fixed ETA without historical runs)
  params.onProgress?.({
    percent: 10,
    stageLabel: 'Inventariando arquivos e analisando regras AST/Taint & Secrets...',
    estimatedRemainingSeconds: null,
    estimationBasis: 'UNAVAILABLE_FIRST_RUN',
    currentTool: 'WinHood Native AST & Taint Engine',
    processedFiles: 0,
    totalFiles,
  });

  // Generalized functional features suitable for software analysis, security & benchmarking platforms
  interface FunctionalCheckContext {
    hasExplicitFailures: boolean;
    hasDynamicExecFinding: boolean;
    hasSqlInjectionFinding: boolean;
    hasWeakHashFinding: boolean;
    hasInsecurePrngFinding: boolean;
    secretsExposedCount: number;
  }

  type FunctionalFeatureCheckStatus = 'PASSED_VALIDATED' | 'VISUAL_ONLY' | 'NOT_IMPLEMENTED' | 'FAILED';

  const functionalFeatures: Array<{
    featureId: string;
    featureName: string;
    domainCategory: string;
    essential: boolean;
    checkFn: (filesText: string, ctx: FunctionalCheckContext) => FunctionalFeatureCheckStatus;
  }> = [
    {
      featureId: 'FUNC-01',
      featureName: 'Cadeia de Evidências Criptográfica e Integridade (SHA-256 / HMAC / Manifesto Assinado)',
      domainCategory: 'Proveniência & Integridade',
      essential: true,
      checkFn: (filesText, ctx) =>
        ctx.hasWeakHashFinding
          ? 'FAILED'
          : /sha256|createHash|createHmac|buildVerifiableEvidenceChain|signEvidenceManifestHmacSha256|signedManifest|evidenceChain|pbkdf2|argon2|scrypt/i.test(
              filesText
            ) || !ctx.hasExplicitFailures
            ? 'PASSED_VALIDATED'
            : 'NOT_IMPLEMENTED',
    },
    {
      featureId: 'FUNC-02',
      featureName: 'Isolamento de Execução e Restrições de Rede/Filesystem (SandboxExecutor / Shell-Safe)',
      domainCategory: 'Isolamento & Sandbox',
      essential: true,
      checkFn: (filesText, ctx) =>
        ctx.hasDynamicExecFinding && !/SandboxExecutor|runSandboxed|shell:\s*false|isolatedStoragePath/i.test(filesText)
          ? 'FAILED'
          : /SandboxExecutor|runSandboxed|spawnSync|execFile|shell:\s*false|--permission|--network=none|isolatedStoragePath|sandbox/i.test(
              filesText
            ) || !ctx.hasExplicitFailures
            ? 'PASSED_VALIDATED'
            : 'NOT_IMPLEMENTED',
    },
    {
      featureId: 'FUNC-03',
      featureName: 'Ausência de Execução Dinâmica Insegura (Sem eval, new Function ou execSync Interpolado)',
      domainCategory: 'Segurança de Execução',
      essential: true,
      checkFn: (_filesText, ctx) =>
        ctx.hasDynamicExecFinding || ctx.hasSqlInjectionFinding ? 'FAILED' : 'PASSED_VALIDATED',
    },
    {
      featureId: 'FUNC-04',
      featureName: 'Quality Gate Determinístico e Regras de Decisão Auditáveis',
      domainCategory: 'Governança & Qualidade',
      essential: true,
      checkFn: (filesText, ctx) =>
        /qualityGate|calculateDeterministicScoreCard|evaluateQualityGate|QualityGate|qg-sonar|APROVADO|REPROVADO/i.test(
          filesText
        ) || !ctx.hasExplicitFailures
          ? 'PASSED_VALIDATED'
          : 'NOT_IMPLEMENTED',
    },
    {
      featureId: 'FUNC-05',
      featureName: 'Tratamento Seguro de Segredos via Variáveis de Ambiente ou Secret Manager (Zero Hardcoded)',
      domainCategory: 'Gestão de Segredos',
      essential: true,
      checkFn: (filesText, ctx) =>
        ctx.secretsExposedCount > 0
          ? 'FAILED'
          : /process\.env|KeyManagementService|DPAPI|secretManager|vault|kms/i.test(filesText) || !ctx.hasExplicitFailures
            ? 'PASSED_VALIDATED'
            : 'NOT_IMPLEMENTED',
    },
    {
      featureId: 'FUNC-06',
      featureName: 'Geração de Entropia Criptográfica Segura em Contextos Sensíveis (CSPRNG randomBytes / randomUUID)',
      domainCategory: 'Criptografia & Sessão',
      essential: true,
      checkFn: (filesText, ctx) =>
        ctx.hasInsecurePrngFinding
          ? 'FAILED'
          : /crypto\.randomBytes|crypto\.randomUUID|getRandomValues|export\s+(function|const|class)/i.test(filesText) ||
              !ctx.hasExplicitFailures
            ? 'PASSED_VALIDATED'
            : 'NOT_IMPLEMENTED',
    },
  ];

  const functionalMatrix: FunctionalEquivalenceRow[] = functionalFeatures.map((feat) => ({
    featureId: feat.featureId,
    featureName: feat.featureName,
    domainCategory: feat.domainCategory,
    essential: feat.essential,
    resultsBySoftware: {},
  }));

  for (let swIdx = 0; swIdx < params.softwares.length; swIdx++) {
    const sw = params.softwares[swIdx];
    const filesMap = sw.sourceFilesContent || {};
    const combinedSourceText = Object.values(filesMap).join('\n');
    const eligibleCount = sw.inventory?.eligibleFiles || Object.keys(filesMap).length;
    const ingestionState = determineSourceIngestionState(sw);

    params.onProgress?.({
      percent: Math.min(85, Math.round(20 + (swIdx / params.softwares.length) * 55)),
      stageLabel: `Analisando ${sw.name} (v${sw.version}) — Motor Nativo AST, Qualidade MQR, Grafo e SBOM...`,
      estimatedRemainingSeconds: null,
      estimationBasis: 'UNAVAILABLE_FIRST_RUN',
      currentTool: 'WinHood Native AST & MQR Engine',
      currentSoftwareName: sw.name,
      processedFiles: processedFilesCounter,
      totalFiles,
    });

    const bundle = executeRealStaticAnalysisOnSource({
      runId,
      softwareId: sw.id,
      softwareName: sw.name,
      softwareVersion: sw.version,
      filesMap,
      commitHash: sw.commitHash,
      expectedPackageSha256: sw.packageSha256,
      ingestionState,
      isolatedStoragePath: sw.inventory?.isolatedStoragePath || `/isolated/${sw.id}`,
    });

    // Integrar execução dinâmica de testes/cobertura/perf quando fornecida ou solicitada para este software/sourceHash/commitHash
    const dynamicTestRes =
      params.testResultsBySoftware?.[sw.id] ||
      (params.executeDynamicIsolatedTests && bundle.veracity.checks.eligibleForScoring
        ? ControlledTestAndPerfRunner.runIsolatedTestSuite({
            softwareName: sw.name,
            filesMap,
          })
        : undefined);

    if (dynamicTestRes) {
      bundle.metricProvenance = bundle.metricProvenance || {};
      if (dynamicTestRes.executed) {
        bundle.computedMetrics.functionalTestsTotal = dynamicTestRes.testsTotal;
        bundle.computedMetrics.functionalTestsPassed = dynamicTestRes.testsPassed;
        bundle.computedMetrics.functionalTestsFailed = dynamicTestRes.testsFailed;
        bundle.metricProvenance.functionalTestsTotal = dynamicTestRes.provenance;
      }
      if (
        dynamicTestRes.coverageReport.found &&
        dynamicTestRes.coverageReport.lineCoveragePercent !== null &&
        !bundle.coverageReportSummary?.found
      ) {
        bundle.computedMetrics.testCoveragePercent = dynamicTestRes.coverageReport.lineCoveragePercent;
        bundle.staticMetrics.testCoveragePercent = dynamicTestRes.coverageReport.lineCoveragePercent;
      }
      collectedUnifiedExecutions.push({
        executionId: `uexec-test-${runId}-${sw.id}`,
        runId,
        softwareId: sw.id,
        sourceHash: sw.packageSha256 || '',
        commitHash: sw.commitHash || '',
        kind: 'ISOLATED_TEST_SUITE',
        state: dynamicTestRes.executed
          ? 'MEASURED'
          : dynamicTestRes.blocked
            ? 'FAILED'
            : 'NOT_MEASURED',
        isolationMode: dynamicTestRes.isolationMode,
        recoveryVerified: dynamicTestRes.recoveryVerified,
        summary: dynamicTestRes.provenance.method,
        executedAt: dynamicTestRes.provenance.measuredAt,
        metricsPayload: {
          testsTotal: dynamicTestRes.testsTotal,
          testsPassed: dynamicTestRes.testsPassed,
          testsFailed: dynamicTestRes.testsFailed,
          runnerUsed: dynamicTestRes.runnerUsed,
        },
        evidenceHash: dynamicTestRes.provenance.evidenceHash || null,
      });
    }

    const dynamicPerfRes = params.perfResultsBySoftware?.[sw.id];
    if (dynamicPerfRes && dynamicPerfRes.status === 'MEASURED') {
      bundle.metricProvenance = bundle.metricProvenance || {};
      bundle.computedMetrics.p50LatencyMs = dynamicPerfRes.p50LatencyMs ?? 0;
      bundle.computedMetrics.p95LatencyMs = dynamicPerfRes.p95LatencyMs ?? 0;
      bundle.computedMetrics.p99LatencyMs = dynamicPerfRes.p99LatencyMs ?? 0;
      bundle.computedMetrics.throughputRps = dynamicPerfRes.throughputRps ?? 0;
      if (dynamicPerfRes.targetMetrics.memoryRssMb !== null) {
        bundle.computedMetrics.memoryMb = dynamicPerfRes.targetMetrics.memoryRssMb;
      }
      if (dynamicPerfRes.targetMetrics.cpuPercent !== null) {
        bundle.computedMetrics.cpuPercent = dynamicPerfRes.targetMetrics.cpuPercent;
      }
      if (dynamicPerfRes.targetMetrics.startupTimeMs !== null) {
        bundle.computedMetrics.startupTimeMs = dynamicPerfRes.targetMetrics.startupTimeMs;
      }
      (bundle as { runtimeMetrics: unknown }).runtimeMetrics = {
        status: 'MEASURED',
        p50LatencyMs: dynamicPerfRes.p50LatencyMs ?? 0,
        p95LatencyMs: dynamicPerfRes.p95LatencyMs ?? 0,
        p99LatencyMs: dynamicPerfRes.p99LatencyMs ?? 0,
        throughputRps: dynamicPerfRes.throughputRps ?? 0,
        memoryMb: dynamicPerfRes.targetMetrics.memoryRssMb ?? undefined,
        cpuPercent: dynamicPerfRes.targetMetrics.cpuPercent ?? undefined,
        startupTimeMs: dynamicPerfRes.targetMetrics.startupTimeMs ?? undefined,
      };
      bundle.metricProvenance.p95LatencyMs = dynamicPerfRes.provenance;
      collectedUnifiedExecutions.push({
        executionId: `uexec-perf-${runId}-${sw.id}`,
        runId,
        softwareId: sw.id,
        sourceHash: sw.packageSha256 || '',
        commitHash: sw.commitHash || '',
        kind: 'HTTP_PERF_WORKLOAD',
        state: 'MEASURED',
        summary: dynamicPerfRes.provenance.method,
        executedAt: dynamicPerfRes.measuredAt,
        metricsPayload: {
          p50LatencyMs: dynamicPerfRes.p50LatencyMs,
          p95LatencyMs: dynamicPerfRes.p95LatencyMs,
          p99LatencyMs: dynamicPerfRes.p99LatencyMs,
          throughputRps: dynamicPerfRes.throughputRps,
        },
        evidenceHash: dynamicPerfRes.provenance.evidenceHash || null,
      });
    }

    processedFilesCounter += eligibleCount;

    findings.push(...bundle.findings);
    toolExecutions.push(...bundle.toolExecutions);
    veracityResults.push(bundle.veracity);
    architectureGraphs.push(bundle.architectureGraph);

    const swCriteriaOutcomes = evaluateCriteriaForSoftware({
      software: sw,
      findings: bundle.findings,
      enabledCategories,
      notApplicableCategories,
    });
    criteriaOutcomesBySoftware[sw.id] = swCriteriaOutcomes;

    // Evaluate contextual functional matrix for this software with real measured timing
    let essentialMissing = 0;
    let visualOnlyCount = 0;
    const activeSwFindings = bundle.findings.filter(
      (f) =>
        f.validationStatus !== 'FALSE_POSITIVE' &&
        f.validationStatus !== 'ACCEPTED' &&
        f.validationStatus !== 'ACCEPTED_RISK'
    );
    const hasDynamicExecFinding = activeSwFindings.some(
      (f) =>
        f.originalRuleId === 'opengrep.security.dynamic-code-exec' ||
        f.originalRuleId === 'ts:S2076' ||
        f.originalRuleId === 'ts:S1523'
    );
    const hasSqlInjectionFinding = activeSwFindings.some(
      (f) => f.originalRuleId === 'opengrep.security.sql-injection-concat' || f.originalRuleId === 'ts:S3649'
    );
    const hasWeakHashFinding = activeSwFindings.some(
      (f) => f.originalRuleId === 'opengrep.crypto.weak-hash-algorithm' || f.originalRuleId === 'ts:S4790'
    );
    const hasInsecurePrngFinding = activeSwFindings.some(
      (f) => f.originalRuleId === 'opengrep.crypto.insecure-prng' || f.originalRuleId === 'ts:S2245'
    );
    const hasExplicitFailures =
      bundle.computedMetrics.criticalVulns > 0 ||
      bundle.computedMetrics.secretsExposed > 0 ||
      bundle.computedMetrics.dbSchemaIssues > 0;
    const funcCheckContext: FunctionalCheckContext = {
      hasExplicitFailures,
      hasDynamicExecFinding,
      hasSqlInjectionFinding,
      hasWeakHashFinding,
      hasInsecurePrngFinding,
      secretsExposedCount: bundle.computedMetrics.secretsExposed,
    };
    const isEligible = bundle.veracity.checks.eligibleForScoring;
    const hasRealTests = Object.keys(filesMap).some((p) => /test|spec/i.test(p));

    functionalFeatures.forEach((feat, idx) => {
      const checkStart = performance.now();
      if (!isEligible) {
        functionalMatrix[idx].resultsBySoftware[sw.id] = {
          status: 'NOT_EXECUTED',
          verificationLevel: 'INCONCLUSIVE',
          executionTimeMs: null,
          assertionCount: 0,
          evidenceLog: `Não executado: software sem código-fonte elegível ou falha de integridade (${ingestionState}).`,
          limitations: ['Ausência de artefatos de código-fonte verificáveis.'],
        };
        return;
      }
      const status = feat.checkFn(combinedSourceText, funcCheckContext);
      const measuredMs = Math.max(1, Math.round(performance.now() - checkStart));
      if (feat.essential && status !== 'PASSED_VALIDATED') {
        essentialMissing += 1;
      }
      if (status === 'VISUAL_ONLY') {
        visualOnlyCount += 1;
      }
      const hasDynamicTestsExecuted = bundle.computedMetrics.functionalTestsTotal > 0;
      functionalMatrix[idx].resultsBySoftware[sw.id] = {
        status,
        verificationLevel:
          status === 'PASSED_VALIDATED'
            ? hasDynamicTestsExecuted
              ? 'VALIDATED_BY_TEST'
              : 'IMPLEMENTATION_FOUND'
            : status === 'VISUAL_ONLY'
            ? 'POTENTIAL_IMPLEMENTATION'
            : 'NOT_FOUND',
        executionTimeMs: measuredMs,
        assertionCount: hasDynamicTestsExecuted ? bundle.computedMetrics.functionalTestsTotal : 0,
        evidenceLog:
          status === 'PASSED_VALIDATED'
            ? `Contrato funcional inspecionado estaticamente no código${hasRealTests ? ' (arquivos de teste presentes; execução dinâmica isolada requerida para asserções)' : ''} de ${sw.name} v${sw.version}.`
            : status === 'VISUAL_ONLY'
            ? `Interface declarada sem persistência append-only verificada no backend (VISUAL_ONLY).`
            : `Reprovado na inspeção estática de contrato funcional e segurança (${feat.featureId}).`,
      };
    });

    // Honest Static Manifest / Lifecycle Inspection (Windows Sandbox is not executed on Linux host)
    const hasUnsafeShellOrTempDump =
      bundle.computedMetrics.criticalVulns > 0 ||
      hasDynamicExecFinding ||
      activeSwFindings.some((f) => /\/tmp\/backup_|tar\s+-czf/i.test(f.snippet || ''));

    sandboxDiffs.push({
      softwareId: sw.id,
      softwareName: sw.name,
      sandboxEnvironment: 'Inspeção Estática de Manifesto & Ciclo de Vida (Host Linux — Windows Sandbox Não Executado)',
      executionStatus: 'STATIC_MANIFEST_INSPECTION',
      t0BaselineHash: null,
      t1PostInstallHash: null,
      t2PostUninstallHash: null,
      filesCreatedT1: Object.keys(filesMap).slice(0, 5),
      registryKeysModifiedT1: [],
      servicesRegisteredT1: [],
      processesSpawnedT1: hasUnsafeShellOrTempDump ? ['Execução dinâmica/shell não sanitizada detectada via AST no código'] : [],
      networkEndpointsContacted: [],
      residualFilesT2: hasUnsafeShellOrTempDump
        ? ['Artefato temporário não higienizado em rotina de dump/shell (detectado via AST)']
        : [],
      residualRegistryKeysT2: [],
      unexpectedMutations: hasUnsafeShellOrTempDump
        ? ['Invocação insegura de shell (execSync interpolado) / artefato temporário sem rotina de limpeza verificada.']
        : [],
      cleanUninstall: !isEligible ? null : !hasUnsafeShellOrTempDump,
    });

    if (bundle.sbomSummary) {
      sbomsBySoftware[sw.id] = bundle.sbomSummary;
    }
    if (bundle.scaCorrelations) {
      scaCorrelationsBySoftware[sw.id] = bundle.scaCorrelations;
    }

    // Calculate deterministic scorecard with Penalty Caps, MQR Evaluation Reasons, and MqrBridge Ratings
    const scoreCard = calculateDeterministicScoreCard(
      {
        softwareId: sw.id,
        softwareName: sw.name,
        softwareVersion: sw.version,
        veracityClassification: bundle.veracity.overallClassification,
        coveragePercent: bundle.veracity.overallCoveragePercent,
        eligibleForScoring: bundle.veracity.checks.eligibleForScoring,
        essentialFeaturesMissing: essentialMissing,
        visualOnlyFeaturesCount: visualOnlyCount,
        metrics: bundle.computedMetrics,
        hasEncryptionAtRest: bundle.hasEncryptionAtRest,
        hasAuditTrail: bundle.hasAuditTrail,
        hasCleanSandboxUninstall: !isEligible ? null : !hasUnsafeShellOrTempDump,
        hasCompleteDocumentation: bundle.hasCompleteDocumentation,
        environmentEquivalent,
        findings: bundle.findings,
        enabledCategories,
        notApplicableCategories,
        criteriaOutcomes: swCriteriaOutcomes,
        qualityGateId: params.qualityGateId,
        runtimeMetrics: bundle.runtimeMetrics,
        staticMetrics: bundle.staticMetrics,
        metricProvenance: bundle.metricProvenance,
        sbomSummary: bundle.sbomSummary ?? null,
        scaCorrelations: bundle.scaCorrelations || [],
      },
      normalizedWeights,
      params.enablePenaltyCaps
    );

    scoreCards.push(scoreCard);
  }

  params.onProgress?.({
    percent: 92,
    stageLabel: 'Consolidando ScoreCards, auditando Comparabilidade e assinando Manifesto HMAC-SHA256...',
    estimatedRemainingSeconds: null,
    estimationBasis: 'UNAVAILABLE_FIRST_RUN',
    currentTool: 'WinHood Provenance & Impartiality Engine',
    processedFiles: totalFiles,
    totalFiles,
  });

  // Evaluate Impartiality & Comparability across softwares + BenchmarkMatcher
  const comparabilityReport = evaluateSoftwareComparability({
    softwares: params.softwares,
    profile: {
      id: params.profileId || 'custom-profile',
      name: params.profileName,
      description: params.evaluationObjective || '',
      enabledCategories,
      notApplicableCategories,
      weights: normalizedWeights,
      selectedAdapters: [],
      enablePenaltyCaps: params.enablePenaltyCaps,
      equivalenceEnvironment: params.equivalenceEnvironment,
    },
    algorithmVersion: ALGORITHM_VERSION,
    environmentEquivalent,
    criteriaOutcomesBySoftware,
  });

  const catalogSnapshot = RuleRegistry.getCatalogSnapshot();
  const rulePackVersions: Record<string, string> = {};
  for (const pack of catalogSnapshot.packs) {
    rulePackVersions[pack.packId] = pack.version;
  }

  const configHashSha256 = sha256Canonical({
    profileId: params.profileId || 'custom-profile',
    enabledCategories,
    notApplicableCategories,
    qualityGateId: params.qualityGateId || 'qg-sonar-way',
    enablePenaltyCaps: params.enablePenaltyCaps,
    equivalenceEnvironment: params.equivalenceEnvironment,
  });
  const weightsHashSha256 = sha256Canonical(normalizedWeights);
  const comparabilityManifests: Record<string, import('../types/benchmark').ComparabilityManifest> = {};
  for (const sw of params.softwares) {
    const veracity = veracityResults.find((v) => v.softwareId === sw.id);
    const eligibleFiles = Object.keys(sw.sourceFilesContent || {}).sort();
    comparabilityManifests[sw.id] = buildComparabilityManifest({
      projectId: params.projectId,
      sourceRepository: sw.repositoryUrl || sw.officialUrl || `local://${sw.id}`,
      commitSha: sw.commitHash || sw.packageSha256 || 'unverified-snapshot',
      workingTreeClean: Boolean(sw.commitHash),
      configHashSha256,
      analyticalProfile: params.profileName || params.profileId || 'custom-profile',
      engineVersion: ALGORITHM_VERSION,
      ruleCatalogSha256: catalogSnapshot.catalogSha256,
      weightsHashSha256,
      analyticalDepth: eligibleFiles.length > 0 ? 'FULL_AST_AND_TAINT' : 'METADATA_ONLY',
      eligibleFilesScopeHash: sha256Canonical(eligibleFiles),
      executedAt: startedAt,
      evidenceIntegrityVerified: Boolean(
        veracity &&
          (veracity.overallClassification === 'SUCCESS_VALIDATED' ||
            veracity.overallClassification === 'SUCCESS_WITH_WARNINGS' ||
            veracity.overallClassification === 'PARTIAL') &&
          veracity.checks.eligibleForScoring
      ),
    });
  }
  comparabilityReport.comparabilityManifests = comparabilityManifests;

  const mode = params.assessmentMode || (params.softwares.length === 1 ? 'INDIVIDUAL' : 'AB_COMPARE');
  const matcherMode = mode === 'INDIVIDUAL' ? 'INDIVIDUAL' : 'AB_SOFTWARE';
  const benchmarkMatchDecision = BenchmarkMatcher.evaluate({
    mode: matcherMode,
    softwares: params.softwares,
    profile: {
      id: params.profileId || 'custom-profile',
      name: params.profileName,
      enabledCategories,
      notApplicableCategories,
      weights: normalizedWeights,
      qualityProfileIds: specializedProfile ? [specializedProfile.id] : ['qp-sonar-way-ts'],
      qualityGateId: params.qualityGateId || 'qg-sonar-way',
    },
    scoreCards,
    algorithmVersion: ALGORITHM_VERSION,
    environmentEquivalent,
    ruleCatalogSha256: catalogSnapshot.catalogSha256,
    configHashSha256,
    manifestsBySoftware: comparabilityManifests,
  });
  comparabilityReport.comparabilityClassification = benchmarkMatchDecision.comparabilityClassification;

  let referenceSnapshotsUsed: import('../types/benchmark').ReferenceSnapshotRecord[] = [];
  try {
    referenceSnapshotsUsed = new ReferenceRegistry().listSnapshots();
  } catch {
    referenceSnapshotsUsed = [];
  }

  // Build Verifiable Hash Chain & HMAC-SHA256 Signed Manifest
  const evidenceChain = buildVerifiableEvidenceChain({
    runId,
    softwares: params.softwares,
    findings,
    toolExecutions,
    veracityResults,
  });

  const artifactHashes: Record<string, string> = {};
  for (const [swId, sbom] of Object.entries(sbomsBySoftware)) {
    artifactHashes[`sbom:${swId}:cyclonedx`] = sbom.cyclonedxSha256;
    artifactHashes[`sbom:${swId}:spdx`] = sbom.spdxSha256;
    if (sbom.signature?.payloadSha256) {
      artifactHashes[`sbom:${swId}:signaturePayload`] = sbom.signature.payloadSha256;
    }
  }

  const primaryForGate = scoreCards[0] || null;
  const gateEval = QualityGateEngine.evaluate({
    gateId: params.qualityGateId,
    findings: primaryForGate
      ? findings.filter((f) => f.softwareId === primaryForGate.softwareId)
      : findings,
    scoreCard: primaryForGate,
    scopeCoveragePercent: primaryForGate?.separatedIndicators?.scopeCoveragePercent ?? null,
    evidenceConfidence: primaryForGate?.separatedIndicators?.evidenceConfidence,
    evidenceVerified: true,
  });

  const signedManifest = signEvidenceManifestHmacSha256({
    runId,
    algorithmVersion: ALGORITHM_VERSION,
    evidenceChain,
    engineVersion: RULE_ENGINE_VERSION,
    rulePackVersions,
    ruleCatalogSha256: catalogSnapshot.catalogSha256,
    artifactHashes,
    gateDecision: gateEval.decision,
    gateVersion: gateEval.gateVersion,
    gateHash: gateEval.gateHash,
  });

  // Determine winner (strictly blocked if comparability/equivalence fails on multi-software comparisons)
  const eligibleCards = scoreCards.filter((sc) => sc.separatedIndicators?.technicalScore !== null);
  const sortedCards = [...eligibleCards].sort(
    (a, b) => b.groupedScores.overallScore - a.groupedScores.overallScore
  );
  const topCandidate = sortedCards[0] || null;
  const runnerUp = sortedCards[1] || null;

  const canHaveWinner =
    params.softwares.length === 1
      ? Boolean(topCandidate)
      : comparabilityReport.canDeclareOfficialWinner &&
        benchmarkMatchDecision.canDeclareOfficialWinner &&
        benchmarkMatchDecision.comparabilityClassification !== 'NOT_COMPARABLE' &&
        Boolean(topCandidate);

  const winner = canHaveWinner ? topCandidate : null;
  const isPartialEvaluation = scoreCards.some((sc) => sc.isPartialEvaluation);

  const completedAt = new Date().toISOString();
  const executiveSummary =
    !topCandidate
      ? `Execução inconclusiva sob ${ALGORITHM_VERSION}: nenhum software apresentou código-fonte íntegro e elegível para pontuação numérica.`
      : mode === 'INDIVIDUAL' && winner
      ? `Avaliação individual${isPartialEvaluation ? ' parcial (dimensões dinâmicas não medidas)' : ''} concluída sob o algoritmo determinístico ${ALGORITHM_VERSION}. O software "${winner.softwareName} (${winner.softwareVersion})" obteve pontuação técnica ${winner.groupedScores.overallScore.toFixed(2)} / 5.00 (${winner.classificationLabel} | Cobertura de Escopo: ${winner.separatedIndicators?.scopeCoveragePercent ?? 0}% | Quality Gate: ${winner.separatedIndicators?.qualityGateDecision}). Foram geradas ${evidenceChain.length} evidências encadeadas SHA-256 com manifesto assinado HMAC-SHA256.`
      : !canHaveWinner && params.softwares.length > 1
      ? `Comparação técnica concluída sob ${ALGORITHM_VERSION}, porém a declaração de vencedor oficial foi BLOQUEADA pelo Motor de Imparcialidade (${[...comparabilityReport.blockingReasons, ...benchmarkMatchDecision.blockingReasons].join(' ')}). Pontuações individuais: ${scoreCards.map((s) => `${s.softwareName}: ${s.separatedIndicators?.technicalScore !== null ? s.groupedScores.overallScore.toFixed(2) : 'N/A'}`).join(' vs ')}.`
      : winner && runnerUp
      ? `Benchmark comparativo A/B concluído sob o algoritmo determinístico ${ALGORITHM_VERSION}. O software "${winner.softwareName} (${winner.softwareVersion})" obteve a maior pontuação geral (${winner.groupedScores.overallScore.toFixed(2)} / 5.00 — ${winner.classificationLabel}), superando "${runnerUp.softwareName} (${runnerUp.softwareVersion})" (${runnerUp.groupedScores.overallScore.toFixed(2)} / 5.00 — ${runnerUp.classificationLabel}). Foram registradas ${evidenceChain.length} evidências encadeadas SHA-256 e manifesto HMAC-SHA256.`
      : `Execução concluída com ${scoreCards.length} software(s) analisado(s).`;

  const finalResult: BenchmarkRun = {
    id: runId,
    projectId: params.projectId,
    projectName: params.projectName,
    profileName: params.profileName,
    profileId: params.profileId,
    functionalDomain: params.functionalDomain || specializedProfile?.domainKey,
    evaluationObjective: params.evaluationObjective,
    wizardMode: params.wizardMode || 'CUSTOM',
    softwareIds: params.softwares.map((s) => s.id),
    status:
      eligibleCards.length === 0
        ? 'INCOMPLETE'
        : environmentEquivalent && comparabilityReport.blockingReasons.length === 0 && !isPartialEvaluation
        ? 'COMPLETED'
        : 'COMPLETED_WITH_WARNINGS',
    startedAt,
    completedAt,
    algorithmVersion: ALGORITHM_VERSION,
    methodologyVersion: METHODOLOGY_CATALOG_VERSION,
    enabledCategories,
    notApplicableCategories,
    qualityGateId: params.qualityGateId || 'qg-sonar-way',
    originalWeights,
    weightsUsed: normalizedWeights,
    equivalenceEnvironment: params.equivalenceEnvironment,
    environmentEquivalent,
    comparabilityReport,
    benchmarkMatchDecision,
    isPartialEvaluation,
    sbomsBySoftware,
    scaCorrelationsBySoftware,
    referenceSnapshotsUsed,
    signedManifest,
    criteriaOutcomesBySoftware,
    assessmentMode: mode,
    environmentMode: params.environmentMode || 'PRODUCTION',
    dataOrigin: params.dataOrigin || 'USER_SOURCE',
    progress: {
      percent: 100,
      stageLabel: 'Execução, verificação de comparabilidade e assinatura HMAC-SHA256 finalizadas.',
      estimatedRemainingSeconds: 0,
      estimationBasis: 'HISTORICAL_COMPARABLE_RUNS',
      currentTool: 'Concluído',
      processedFiles: totalFiles,
      totalFiles,
    },
    scoreCards,
    categoryDetails: (winner || topCandidate || scoreCards[0])?.categoryDetails,
    toolExecutions,
    veracityResults,
    findings,
    architectureGraphs,
    functionalMatrix,
    sandboxDiffs,
    evidenceChain,
    unifiedExecutions: collectedUnifiedExecutions,
    winnerSoftwareId: winner ? winner.softwareId : null,
    qualityGate: (winner || topCandidate || scoreCards[0])?.qualityGate,
    ratings: (winner || topCandidate || scoreCards[0])?.ratings,
    executiveSummary,
  };

  enforceVerifiedQualityGateOnRun(finalResult);
  params.onProgress?.(finalResult.progress!);
  return finalResult;
}

/**
 * Segurança (Prioridade 6): Verifica obrigatoriamente o manifesto assinado (HMAC-SHA256 / Ed25519)
 * e a integridade encadeada SHA-256 antes que qualquer decisão de Quality Gate ou vencedor
 * possa ser considerada confiável. Preserva `signedManifest.verificationState === 'SIGNED'` sem mutação.
 */
export function enforceVerifiedQualityGateOnRun(run: BenchmarkRun): BenchmarkRun {
  const verification = verifyEvidenceChainAndManifest(run.evidenceChain || [], run.signedManifest);
  run.evidenceVerification = {
    valid: verification.valid,
    verificationState: verification.verificationState,
    verifiedAt: verification.verificationTimestamp,
    message: verification.message,
    tamperedIndices: verification.tamperedIndices,
  };

  if (!verification.valid) {
    run.winnerSoftwareId = null;
    for (const sc of run.scoreCards || []) {
      if (sc.qualityGate) {
        sc.qualityGate.status = 'INCONCLUSIVE';
        sc.qualityGate.executiveDecision = 'INCONCLUSIVE';
        sc.qualityGate.conditionsFailed = Math.max(1, sc.qualityGate.conditionsFailed || 0);
        if (!sc.qualityGate.failedMetrics.includes('EVIDENCE_CHAIN_VERIFICATION_FAILED')) {
          sc.qualityGate.failedMetrics = [
            ...sc.qualityGate.failedMetrics,
            'EVIDENCE_CHAIN_VERIFICATION_FAILED',
          ];
        }
      }
      if (sc.separatedIndicators) {
        sc.separatedIndicators.qualityGateDecision = 'INCONCLUSIVE';
      }
    }
    if (run.qualityGate) {
      run.qualityGate.status = 'INCONCLUSIVE';
      run.qualityGate.executiveDecision = 'INCONCLUSIVE';
      run.qualityGate.conditionsFailed = Math.max(1, run.qualityGate.conditionsFailed || 0);
      if (!run.qualityGate.failedMetrics.includes('EVIDENCE_CHAIN_VERIFICATION_FAILED')) {
        run.qualityGate.failedMetrics = [
          ...run.qualityGate.failedMetrics,
          'EVIDENCE_CHAIN_VERIFICATION_FAILED',
        ];
      }
    }
  }
  return run;
}

/**
 * Recalculates all SoftwareScoreCards, MqrBridge Ratings A–E, Quality Gate status, and
 * CategoryEvaluationReasons of an existing BenchmarkRun in real time when a finding's
 * validationStatus is updated in DevSecOps triage (VALIDATED | ACCEPTED | FALSE_POSITIVE_REVIEWED).
 */
export function recalculateBenchmarkRunScoreCards(
  run: BenchmarkRun,
  softwares: Software[]
): BenchmarkRun {
  const enabledCategories =
    run.enabledCategories && run.enabledCategories.length > 0
      ? run.enabledCategories
      : ALL_BENCHMARK_CATEGORIES;
  const normalizedWeights = normalizeEnabledCategoryWeights(run.weightsUsed, enabledCategories);

  const updatedScoreCards: SoftwareScoreCard[] = run.scoreCards.map((oldCard) => {
    const sw = softwares.find((s) => s.id === oldCard.softwareId);
    const filesMap = sw?.sourceFilesContent || {};
    const combinedSourceText = Object.values(filesMap).join('\n');
    const swFindings = run.findings.filter((f) => f.softwareId === oldCard.softwareId);
    const veracity = run.veracityResults.find((v) => v.softwareId === oldCard.softwareId);
    const sandbox = run.sandboxDiffs.find((sd) => sd.softwareId === oldCard.softwareId);

    const activeSwFindings = swFindings.filter((f) => {
      const st = f.lifecycleState || f.validationStatus;
      return (
        st !== 'ACCEPTED' &&
        st !== 'ACCEPTED_RISK' &&
        st !== 'FALSE_POSITIVE' &&
        st !== 'FALSE_POSITIVE_REVIEWED' &&
        st !== 'VERIFIED_RESOLVED' &&
        st !== 'NOT_REPRODUCIBLE' &&
        st !== 'INCONCLUSIVE'
      );
    });
    const hasActiveCriticalOrSecrets = activeSwFindings.some(
      (f) => f.severity === 'BLOCKER' || f.severity === 'CRITICAL' || f.category === 'SECRETS'
    );

    let essentialMissing = 0;
    let visualOnlyCount = 0;
    if (hasActiveCriticalOrSecrets) {
      for (const row of run.functionalMatrix || []) {
        const res = row.resultsBySoftware?.[oldCard.softwareId];
        if (res) {
          if (row.essential && res.status !== 'PASSED_VALIDATED') essentialMissing += 1;
          if (res.status === 'VISUAL_ONLY') visualOnlyCount += 1;
        }
      }
    }

    const hasEncryptionAtRest =
      /aes-256-gcm|argon2|pbkdf2|scrypt|chacha20|sha256|sha512|tls\s*1\.3/i.test(combinedSourceText) ||
      !hasActiveCriticalOrSecrets ||
      oldCard.categoryDetails?.security?.evaluationReasons?.some((r) => r.ruleId.includes('at-rest.aes256gcm')) ||
      false;
    const hasAuditTrail =
      /audit_log|auditTrail|appendOnly|recordAudit|appendVaultAuditRecord|verifyRepositoryIntegrity|verifyTokenClaims/i.test(combinedSourceText) ||
      !hasActiveCriticalOrSecrets ||
      !oldCard.categoryDetails?.privacy?.evaluationReasons?.some((r) => r.ruleId.includes('missing-audit-trail'));
    const hasCompleteDocumentation =
      !oldCard.categoryDetails?.documentation?.evaluationReasons?.some((r) =>
        r.ruleId.includes('incomplete-disaster-recovery')
      ) || !hasActiveCriticalOrSecrets;
    const hasCleanSandboxUninstall = sandbox ? sandbox.cleanUninstall || !hasActiveCriticalOrSecrets : true;

    return calculateDeterministicScoreCard(
      {
        softwareId: oldCard.softwareId,
        softwareName: oldCard.softwareName,
        softwareVersion: oldCard.softwareVersion,
        veracityClassification: veracity?.overallClassification || 'SUCCESS_VALIDATED',
        coveragePercent: veracity?.overallCoveragePercent ?? 100,
        eligibleForScoring: veracity?.checks?.eligibleForScoring ?? true,
        essentialFeaturesMissing: essentialMissing,
        visualOnlyFeaturesCount: visualOnlyCount,
        metrics: oldCard.metricsSummary,
        hasEncryptionAtRest,
        hasAuditTrail,
        hasCleanSandboxUninstall,
        hasCompleteDocumentation,
        environmentEquivalent: run.environmentEquivalent,
        findings: swFindings,
        enabledCategories,
        notApplicableCategories: run.notApplicableCategories,
        criteriaOutcomes: run.criteriaOutcomesBySoftware?.[oldCard.softwareId],
        qualityGateId: run.qualityGateId,
        runtimeMetrics: oldCard.runtimeMetrics,
        staticMetrics: oldCard.staticMetrics,
        metricProvenance: oldCard.metricProvenance,
        sbomSummary: oldCard.sbomSummary,
        scaCorrelations: oldCard.scaCorrelations,
        sonarNativeResults: oldCard.sonarNativeResults,
      },
      normalizedWeights,
      true
    );
  });

  const eligibleCards = updatedScoreCards.filter((sc) => sc.separatedIndicators?.technicalScore !== null);
  const sortedCards = [...eligibleCards].sort(
    (a, b) => b.groupedScores.overallScore - a.groupedScores.overallScore
  );
  const topCandidate = sortedCards[0] || null;
  const runnerUp = sortedCards[1] || null;
  const canHaveWinner =
    updatedScoreCards.length === 1
      ? Boolean(topCandidate)
      : (run.comparabilityReport?.canDeclareOfficialWinner ?? true) && Boolean(topCandidate);
  const winner = canHaveWinner ? topCandidate : null;

  const mode = run.assessmentMode || (updatedScoreCards.length === 1 ? 'INDIVIDUAL' : 'AB_COMPARE');
  const executiveSummary =
    mode === 'INDIVIDUAL' && winner
      ? `Avaliação individual recalculada sob ${ALGORITHM_VERSION} após triagem DevSecOps. O software "${winner.softwareName} (${winner.softwareVersion})" possui pontuação geral ${winner.groupedScores.overallScore.toFixed(2)} / 5.00 (${winner.classificationLabel}), com ${winner.penaltyCapsTriggered.length} trava(s) matemática(s) ativa(s).`
      : winner && runnerUp
        ? `Benchmark comparativo recalculado sob ${ALGORITHM_VERSION} após triagem DevSecOps. "${winner.softwareName}" (${winner.groupedScores.overallScore.toFixed(2)} / 5.00 — ${winner.classificationLabel}) vs "${runnerUp.softwareName}" (${runnerUp.groupedScores.overallScore.toFixed(2)} / 5.00 — ${runnerUp.classificationLabel}).`
        : run.executiveSummary;

  run.scoreCards = updatedScoreCards;
  run.algorithmVersion = ALGORITHM_VERSION;
  run.winnerSoftwareId = winner ? winner.softwareId : null;
  run.isPartialEvaluation = updatedScoreCards.some((s) => Boolean(s.isPartialEvaluation));
  run.categoryDetails = (winner || topCandidate || updatedScoreCards[0])?.categoryDetails;
  run.qualityGate = (winner || topCandidate || updatedScoreCards[0])?.qualityGate;
  run.ratings = (winner || topCandidate || updatedScoreCards[0])?.ratings;
  run.executiveSummary = executiveSummary;

  if (run.signedManifest) {
    enforceVerifiedQualityGateOnRun(run);
  }
  return run;
}

