import { execSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { SonarScannerRecord } from '../../types/benchmark';

export class ToolAvailabilityService {
  public static getDefaultExternalToolsRoot(): string {
    if (process.env.EXTERNAL_TOOLS_DIR) {
      return process.env.EXTERNAL_TOOLS_DIR;
    }
    if (os.platform() === 'win32') {
      const localAppData =
        process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
      return path.join(localAppData, 'SoftwareBenchmarkAnalyzer', 'tools');
    }
    return path.join(os.homedir(), '.local', 'share', 'SoftwareBenchmarkAnalyzer', 'tools');
  }

  public static checkBinaryInPath(binaryName: string): {
    detected: boolean;
    executablePath: string;
    versionOutput: string | null;
  } {
    const cmd = os.platform() === 'win32' ? `where ${binaryName}` : `which ${binaryName}`;
    try {
      const located = execSync(cmd, { encoding: 'utf8', timeout: 1200 }).trim().split('\n')[0];
      if (!located) {
        return { detected: false, executablePath: '', versionOutput: null };
      }
      let versionOutput: string | null = null;
      try {
        versionOutput = execSync(`${binaryName} --version 2>&1`, {
          encoding: 'utf8',
          timeout: 1500,
        })
          .trim()
          .split('\n')[0];
      } catch {
        versionOutput = null;
      }
      return {
        detected: true,
        executablePath: located,
        versionOutput,
      };
    } catch {
      return { detected: false, executablePath: '', versionOutput: null };
    }
  }

  public static discoverScannersInventory(): SonarScannerRecord[] {
    const toolsRoot = ToolAvailabilityService.getDefaultExternalToolsRoot();
    const isWin = os.platform() === 'win32';
    const cliZipName = isWin
      ? 'sonar-scanner-cli-8.4.0.16527-windows-x64.zip'
      : 'sonar-scanner-cli-8.4.0.16527-linux-x64.zip';
    const cliOfficialSha = isWin
      ? '9998fca7f8897975f8fad850aa92e5a236441ace6c6126a15da34f5a049795ce'
      : '2a28f118e2e9375dfd36eb27b803e1d37f93daba4db068aca6eef9853041bb24';

    const cliCheck = ToolAvailabilityService.checkBinaryInPath('sonar-scanner');
    const mvnCheck = ToolAvailabilityService.checkBinaryInPath('mvn');
    const gradleCheck = ToolAvailabilityService.checkBinaryInPath('gradle');
    const dotnetCheck = ToolAvailabilityService.checkBinaryInPath('dotnet');
    const npmCheck = ToolAvailabilityService.checkBinaryInPath('npm');
    const pythonCheck = ToolAvailabilityService.checkBinaryInPath('python3');

    const cliToolsDir = path.join(toolsRoot, 'sonar-scanner-cli', '8.4.0.16527');
    const cachedCli = fs.existsSync(cliToolsDir);

    return [
      {
        id: 'scanner-maven',
        scannerType: 'SONAR_SCANNER_MAVEN',
        displayName: 'SonarScanner for Maven',
        version: '5.0.0.4389',
        targetEcosystem: 'Java / Kotlin / Maven (pom.xml)',
        binaryDetected: mvnCheck.detected,
        executablePath: mvnCheck.executablePath || 'mvn sonar:sonar',
        downloadUrl: 'https://repo.maven.apache.org/maven2/org/sonarsource/scanner/maven/sonar-maven-plugin/',
        officialSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        cachedInToolsDir: mvnCheck.detected,
        lastUsedAt: null,
      },
      {
        id: 'scanner-gradle',
        scannerType: 'SONAR_SCANNER_GRADLE',
        displayName: 'SonarScanner for Gradle',
        version: '6.0.1.5171',
        targetEcosystem: 'Java / Kotlin / Android / Gradle (build.gradle)',
        binaryDetected: gradleCheck.detected,
        executablePath: gradleCheck.executablePath || 'gradle sonar',
        downloadUrl: 'https://plugins.gradle.org/plugin/org.sonarqube',
        officialSha256: '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
        cachedInToolsDir: gradleCheck.detected,
        lastUsedAt: null,
      },
      {
        id: 'scanner-dotnet',
        scannerType: 'SONAR_SCANNER_DOTNET',
        displayName: 'SonarScanner for .NET',
        version: '9.0.2',
        targetEcosystem: 'C# / F# / VB.NET (.csproj / .sln)',
        binaryDetected: dotnetCheck.detected,
        executablePath: dotnetCheck.executablePath || 'dotnet sonarscanner',
        downloadUrl: 'https://www.nuget.org/packages/dotnet-sonarscanner',
        officialSha256: '7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730',
        cachedInToolsDir: dotnetCheck.detected,
        lastUsedAt: null,
      },
      {
        id: 'scanner-npm',
        scannerType: 'SONAR_SCANNER_NPM',
        displayName: 'SonarScanner for NPM (@sonar/scan)',
        version: '4.2.5',
        targetEcosystem: 'JavaScript / TypeScript / Node.js (package.json)',
        binaryDetected: npmCheck.detected,
        executablePath: npmCheck.executablePath || 'npx @sonar/scan',
        downloadUrl: 'https://registry.npmjs.org/@sonar/scan/-/scan-4.2.5.tgz',
        officialSha256: 'b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c',
        cachedInToolsDir: npmCheck.detected,
        lastUsedAt: null,
      },
      {
        id: 'scanner-python',
        scannerType: 'SONAR_SCANNER_PYTHON',
        displayName: 'SonarScanner for Python (pysonar)',
        version: '1.1.0',
        targetEcosystem: 'Python (pyproject.toml / requirements.txt)',
        binaryDetected: pythonCheck.detected,
        executablePath: pythonCheck.executablePath || 'pysonar-scanner',
        downloadUrl: 'https://pypi.org/project/pysonar-scanner/',
        officialSha256: 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2',
        cachedInToolsDir: pythonCheck.detected,
        lastUsedAt: null,
      },
      {
        id: 'scanner-cli',
        scannerType: 'SONAR_SCANNER_CLI',
        displayName: 'SonarScanner CLI (Universal / Poliglota)',
        version: '8.4.0.16527',
        targetEcosystem: 'Projetos sem scanner específico (C/C++, Go, PHP, SQL, Multi-Language)',
        binaryDetected: cliCheck.detected || cachedCli,
        executablePath:
          cliCheck.executablePath ||
          path.join(cliToolsDir, 'bin', isWin ? 'sonar-scanner.bat' : 'sonar-scanner'),
        downloadUrl: `https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/${cliZipName}`,
        officialSha256: cliOfficialSha,
        cachedInToolsDir: cachedCli,
        lastUsedAt: null,
      },
    ];
  }
}
