import type { Software, SonarScannerRecord, SonarScannerType } from '../../types/benchmark';
import { computeSha256 } from '../../engine/scoringEngine';
import { ToolAvailabilityService } from '../../services/tools/ToolAvailabilityService';

export interface GeneratedScannerConfiguration {
  scannerType: SonarScannerType;
  scannerVersion: string;
  projectKey: string;
  projectName: string;
  projectBaseDir: string;
  sources: string;
  tests: string;
  exclusions: string;
  coverageExclusions: string;
  hostUrl: string;
  sarifReportPaths: string[];
  exclusionReasonsRecorded: string[];
  scmFullCloneAvailable: boolean;
  scmLimitationWarning: string | null;
  propertiesContent: string;
  propertiesRecord: Record<string, string>;
  configSha256: string;
  commandLineSafePreview: string;
}

/**
 * SonarScannerManager (Seção 3, 3.1, 3.2, 3.3 e 3.4)
 * Seleciona automaticamente o scanner oficial mais adequado para cada tecnologia
 * (Maven, Gradle, .NET, NPM, Python ou SonarScanner CLI), gera a configuração
 * reprodutível e garante que SONAR_TOKEN seja passado apenas via variável de ambiente.
 */
export class SonarScannerManager {
  public static listScanners(): SonarScannerRecord[] {
    return ToolAvailabilityService.discoverScannersInventory();
  }

  /**
   * Seleção automática do scanner mais adequado (Seção 3):
   * Prioriza Maven -> Gradle -> .NET -> NPM -> Python -> SonarScanner CLI.
   */
  public static selectOptimalScannerForSoftware(software: Software): {
    scannerType: SonarScannerType;
    scannerVersion: string;
    reason: string;
  } {
    const filePaths = (software.inventory?.files || []).map((f) =>
      f.relativePath.toLowerCase()
    );
    const langs = (software.languages || []).map((l) => l.toLowerCase());

    if (filePaths.some((p) => p.endsWith('pom.xml'))) {
      return {
        scannerType: 'SONAR_SCANNER_MAVEN',
        scannerVersion: '5.0.0.4389',
        reason: 'Detectado manifesto Maven (pom.xml) na árvore do projeto.',
      };
    }

    if (
      filePaths.some(
        (p) => p.endsWith('build.gradle') || p.endsWith('build.gradle.kts')
      )
    ) {
      return {
        scannerType: 'SONAR_SCANNER_GRADLE',
        scannerVersion: '6.0.1.5171',
        reason: 'Detectado script de construção Gradle (build.gradle / build.gradle.kts).',
      };
    }

    if (
      filePaths.some((p) => p.endsWith('.csproj') || p.endsWith('.sln')) ||
      langs.includes('c#')
    ) {
      return {
        scannerType: 'SONAR_SCANNER_DOTNET',
        scannerVersion: '9.0.2',
        reason: 'Detectado ecossistema .NET / C# (.csproj / .sln).',
      };
    }

    if (
      filePaths.some((p) => p.endsWith('package.json')) ||
      langs.includes('typescript') ||
      langs.includes('javascript')
    ) {
      return {
        scannerType: 'SONAR_SCANNER_NPM',
        scannerVersion: '4.2.5',
        reason: 'Detectado projeto Node.js / TypeScript / JavaScript com package.json (@sonar/scan).',
      };
    }

    if (
      filePaths.some(
        (p) =>
          p.endsWith('pyproject.toml') ||
          p.endsWith('requirements.txt') ||
          p.endsWith('setup.py')
      ) ||
      langs.includes('python')
    ) {
      return {
        scannerType: 'SONAR_SCANNER_PYTHON',
        scannerVersion: '1.1.0',
        reason: 'Detectado projeto Python (pyproject.toml / requirements.txt).',
      };
    }

    return {
      scannerType: 'SONAR_SCANNER_CLI',
      scannerVersion: '8.4.0.16527',
      reason:
        'Projeto poliglota ou sem ferramenta de build específica; selecionado SonarScanner CLI universal.',
    };
  }

  /**
   * Gera a configuração oficial do SonarScanner (Seção 3.2, 3.3 e 3.4).
   * - Não aplica exclusões silenciosas sem registrar motivos técnicos.
   * - Nunca coloca `sonar.token` na linha de comando nem no arquivo versionado;
   *   utiliza exclusivamente variável de ambiente `SONAR_TOKEN`.
   */
  public static prepareProjectScannerConfig(params: {
    software: Software;
    role: 'SOFTWARE_A' | 'SOFTWARE_B';
    serverUrl: string;
    branch?: string;
    sarifReportPaths?: string[];
    customExclusions?: string[];
    customExclusionReason?: string;
  }): GeneratedScannerConfiguration {
    const { software, role, serverUrl } = params;
    const selected = SonarScannerManager.selectOptimalScannerForSoftware(software);
    const cleanSlug = software.name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '');
    const projectKey = `winhood-${role.toLowerCase().replace('_', '-')}-${cleanSlug}`;
    const projectBaseDir =
      software.inventory?.isolatedStoragePath || `/isolated_artifacts/${software.id}`;

    const filePaths = (software.inventory?.files || []).map((f) => f.relativePath);
    const hasSrcDir = filePaths.some((p) => p.startsWith('src/'));
    const hasTestsDir = filePaths.some(
      (p) => p.startsWith('tests/') || p.startsWith('test/')
    );

    const sources = hasSrcDir ? 'src' : '.';
    const tests = hasTestsDir ? 'tests' : '';

    // Avaliar SCM / Blame (Seção 3.2)
    const hasGitMetadata = filePaths.some((p) => p.startsWith('.git/'));
    const scmFullCloneAvailable =
      software.sourceType === 'GIT_REPO' && hasGitMetadata;
    const scmLimitationWarning = scmFullCloneAvailable
      ? null
      : 'Histórico SCM (.git) completo não está presente no artefato isolado (ingestão via snapshot/upload ou clone raso). Informações de blame por autor e detecção automática de New Code por branch Git podem ser limitadas; o commit de referência foi registrado explicitamente nos metadados da análise.';

    // Não aplicar exclusões automaticamente sem registrar motivos (Seção 3.3)
    const exclusionReasonsRecorded: string[] = [];
    const exclusionsList: string[] = [];
    if (params.customExclusions && params.customExclusions.length > 0) {
      exclusionsList.push(...params.customExclusions);
      exclusionReasonsRecorded.push(
        params.customExclusionReason ||
          `Exclusões definidas explicitamente pelo operador: ${params.customExclusions.join(', ')}`
      );
    } else {
      exclusionReasonsRecorded.push(
        'Nenhuma exclusão automática aplicada sobre arquivos de produção ou testes para preservar fidelidade integral do benchmark.'
      );
    }

    const sarifPaths = params.sarifReportPaths || [];
    const propertiesRecord: Record<string, string> = {
      'sonar.projectKey': projectKey,
      'sonar.projectName': `${software.name} (${role})`,
      'sonar.projectVersion': software.version,
      'sonar.projectBaseDir': projectBaseDir,
      'sonar.sources': sources,
      'sonar.sourceEncoding': 'UTF-8',
      'sonar.host.url': serverUrl,
      'sonar.revision': software.commitHash,
    };

    if (tests) {
      propertiesRecord['sonar.tests'] = tests;
    }
    if (exclusionsList.length > 0) {
      propertiesRecord['sonar.exclusions'] = exclusionsList.join(',');
    }
    if (sarifPaths.length > 0) {
      propertiesRecord['sonar.sarifReportPaths'] = sarifPaths.join(',');
    }

    const lines = [
      '# Gerado pelo WinHood Software Benchmark & Quality Analyzer',
      `# Data: ${new Date().toISOString()}`,
      '# SEGURANÇA: O token de autenticação (SONAR_TOKEN) NÃO é gravado neste arquivo nem na linha de comando.',
      '# Ele é injetado exclusivamente via variável de ambiente segura no worker backend.',
      ...Object.entries(propertiesRecord).map(([k, v]) => `${k}=${v}`),
    ];
    const propertiesContent = lines.join('\n');
    const configSha256 = computeSha256(propertiesContent);

    let cmdPreview = `SONAR_TOKEN="••••••••" sonar-scanner -Dproject.settings=sonar-project.properties`;
    if (selected.scannerType === 'SONAR_SCANNER_MAVEN') {
      cmdPreview = `SONAR_TOKEN="••••••••" mvn sonar:sonar -Dsonar.projectKey=${projectKey} -Dsonar.host.url=${serverUrl}`;
    } else if (selected.scannerType === 'SONAR_SCANNER_GRADLE') {
      cmdPreview = `SONAR_TOKEN="••••••••" gradle sonar -Dsonar.projectKey=${projectKey} -Dsonar.host.url=${serverUrl}`;
    } else if (selected.scannerType === 'SONAR_SCANNER_DOTNET') {
      cmdPreview = `SONAR_TOKEN="••••••••" dotnet sonarscanner begin /k:"${projectKey}" /d:sonar.host.url="${serverUrl}" && dotnet build && dotnet sonarscanner end`;
    } else if (selected.scannerType === 'SONAR_SCANNER_NPM') {
      cmdPreview = `SONAR_TOKEN="••••••••" npx @sonar/scan -Dsonar.projectKey=${projectKey} -Dsonar.host.url=${serverUrl}`;
    } else if (selected.scannerType === 'SONAR_SCANNER_PYTHON') {
      cmdPreview = `SONAR_TOKEN="••••••••" pysonar-scanner -Dsonar.projectKey=${projectKey} -Dsonar.host.url=${serverUrl}`;
    }

    return {
      scannerType: selected.scannerType,
      scannerVersion: selected.scannerVersion,
      projectKey,
      projectName: `${software.name} (${role})`,
      projectBaseDir,
      sources,
      tests,
      exclusions: exclusionsList.join(','),
      coverageExclusions: '',
      hostUrl: serverUrl,
      sarifReportPaths: sarifPaths,
      exclusionReasonsRecorded,
      scmFullCloneAvailable,
      scmLimitationWarning,
      propertiesContent,
      propertiesRecord,
      configSha256,
      commandLineSafePreview: cmdPreview,
    };
  }
}
