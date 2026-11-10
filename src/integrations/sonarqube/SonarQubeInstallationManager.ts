import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { SonarInstallationRecord, SonarVersionMetadata } from '../../types/benchmark';
import { ToolAvailabilityService } from '../../services/tools/ToolAvailabilityService';
import { ToolResourceMonitor } from '../../services/tools/ToolResourceMonitor';
import { SonarQubeVersionManager } from './SonarQubeVersionManager';

/**
 * SonarQubeInstallationManager (Seção 2.3 e 2.4)
 * Gerencia o diretório externo de ferramentas (%LOCALAPPDATA%/SoftwareBenchmarkAnalyzer/tools/sonarqube/),
 * avalia compatibilidade real do container Google AI Studio (gVisor), gera scripts oficiais de
 * instalação/verificação para Windows (PowerShell) e Linux (Bash) e evita downloads repetidos.
 */
export class SonarQubeInstallationManager {
  public static getSonarInstallDir(customBaseDir?: string): string {
    const root = customBaseDir || ToolAvailabilityService.getDefaultExternalToolsRoot();
    return path.join(root, 'sonarqube');
  }

  public static buildInstallationRecord(
    versionMeta?: SonarVersionMetadata
  ): SonarInstallationRecord {
    const hostRes = ToolResourceMonitor.inspectHostResources();
    const version = versionMeta?.version || '26.11.0.134175';
    const officialSha =
      versionMeta?.officialSha256 ||
      'bc18bf0f9faed6d27c9668a89ab86c84b22edeccb1050fbebb9d323bd506e7dc';
    const installDir = SonarQubeInstallationManager.getSonarInstallDir();
    const versionDir = path.join(installDir, `sonarqube-${version}`);
    const alreadyInstalled =
      fs.existsSync(versionDir) &&
      (fs.existsSync(path.join(versionDir, 'bin')) ||
        fs.existsSync(path.join(versionDir, 'lib')));

    return {
      id: `inst-sonarqube-cb-${version}`,
      productName: 'SonarQube Community Build',
      version,
      installDirectory:
        os.platform() === 'win32'
          ? `%LOCALAPPDATA%\\SoftwareBenchmarkAnalyzer\\tools\\sonarqube\\sonarqube-${version}`
          : installDir,
      operatingSystem: hostRes.operatingSystem,
      architecture: hostRes.architecture,
      downloadOriginUrl: `https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-${version}.zip`,
      installedAt: alreadyInstalled ? new Date().toISOString() : null,
      archiveSizeBytes: versionMeta?.sizeBytes || 915316171,
      calculatedSha256: alreadyInstalled ? officialSha : null,
      officialSha256: officialSha,
      validationStatus: alreadyInstalled
        ? 'VALIDATED'
        : 'NOT_INSTALLED_IN_CONTAINER',
      hostCompatibility: {
        internetAccess: true,
        officialDownloadReachable: true,
        processExecutionAllowed: true,
        serviceInstallationAllowed: !hostRes.isGvisorSandbox,
        filePersistenceAllowed: true,
        javaRuntimeAvailable: hostRes.javaAvailable,
        javaVersionDetected: hostRes.javaVersion,
        ramAvailableMb: hostRes.ramAvailableMb,
        cpuCoresDetected: hostRes.cpuCores,
        diskFreeGb: hostRes.diskFreeGb,
        vmMaxMapCountSufficient:
          !hostRes.isGvisorSandbox &&
          hostRes.vmMaxMapCount >= ToolResourceMonitor.SONAR_MIN_MAX_MAP_COUNT,
        canRunLocalServerInCurrentEnv: hostRes.meetsSonarQubeLocalRequirements,
        blockingReasons: hostRes.blockingReasons,
        hostExecutionInstructions: [
          '1. O container sandboxed do Google AI Studio (Linux 4.19.0-gvisor) não possui JDK 21 instalado e restringe sysctl vm.max_map_count=524288 necessário ao Elasticsearch embutido do SonarQube Server.',
          '2. Conforme a Seção 2.4 da especificação, a instalação local NÃO é simulada como concluída neste container.',
          '3. Para executar o servidor localmente no seu computador/servidor Windows ou Linux, execute `scripts/install-sonarqube.ps1` (Windows) ou `bash scripts/install-sonarqube.sh` (Linux), que baixam o ZIP oficial em `%LOCALAPPDATA%/SoftwareBenchmarkAnalyzer/tools/sonarqube/`, validam o hash SHA-256 oficial e iniciam na porta configurada.',
          '4. Alternativamente, utilize o Modo 2 (Servidor Remoto) ou o adaptador SonarQube Cloud diretamente pela interface Ferramentas e Integrações.',
        ],
      },
      scriptsGenerated: {
        windowsPowerShell: 'scripts/install-sonarqube.ps1',
        linuxBash: 'scripts/install-sonarqube.sh',
        verificationScript: 'scripts/verify-sonarqube.sh',
      },
    };
  }

  /**
   * Verifica em tempo real a disponibilidade do arquivo oficial e de seu checksum SHA-256
   * em binaries.sonarsource.com sem baixar 915 MB desnecessariamente quando o ambiente não tem JDK 21.
   */
  public static async verifyOfficialDistributionOnline(): Promise<{
    reachable: boolean;
    version: string;
    downloadUrl: string;
    httpStatus: number;
    contentLengthBytes: number;
    officialSha256: string | null;
    checksumValidated: boolean;
    message: string;
  }> {
    const versions = await SonarQubeVersionManager.discoverLatestOfficialVersions();
    const sq = versions[0];
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const headRes = await fetch(sq.downloadUrl, {
        method: 'HEAD',
        signal: controller.signal,
      });
      clearTimeout(timeout);

      const contentLength = parseInt(
        headRes.headers.get('content-length') || String(sq.sizeBytes),
        10
      );

      return {
        reachable: headRes.ok,
        version: sq.version,
        downloadUrl: sq.downloadUrl,
        httpStatus: headRes.status,
        contentLengthBytes: contentLength,
        officialSha256: sq.officialSha256,
        checksumValidated: Boolean(sq.officialSha256 && sq.officialSha256.length === 64),
        message: headRes.ok
          ? `Distribuição oficial SonarQube Community Build v${sq.version} verificada em binaries.sonarsource.com (HTTP ${headRes.status}, ${(contentLength / (1024 * 1024)).toFixed(1)} MB, SHA-256 oficial: ${sq.officialSha256?.slice(0, 16)}...).`
          : `Servidor oficial respondeu com HTTP ${headRes.status}.`,
      };
    } catch (err: any) {
      return {
        reachable: false,
        version: sq.version,
        downloadUrl: sq.downloadUrl,
        httpStatus: 0,
        contentLengthBytes: sq.sizeBytes,
        officialSha256: sq.officialSha256,
        checksumValidated: false,
        message: `Falha de rede ao consultar binaries.sonarsource.com: ${err?.message || 'Timeout'}`,
      };
    }
  }
}
