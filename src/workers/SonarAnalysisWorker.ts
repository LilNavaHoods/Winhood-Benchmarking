import type {
  Software,
  SonarABComparisonResult,
  SonarAndToolsDatabaseBundle,
} from '../types/benchmark';
import { SonarQubeIntegrationService } from '../integrations/sonarqube/SonarQubeAdapter';

/**
 * SonarAnalysisWorker (Seção 11.8 e Seção 12)
 * Worker assíncrono controlado pelo backend para executar análises A/B do SonarQube
 * fora do ciclo síncrono bloqueante, respeitando a fila de concorrência do ExternalToolLifecycleManager.
 */
export class SonarAnalysisWorker {
  private sonarService: SonarQubeIntegrationService;

  constructor(sonarService: SonarQubeIntegrationService) {
    this.sonarService = sonarService;
  }

  public async enqueueABComparisonJob(params: {
    softwareA: Software;
    softwareB: Software;
    runId: string;
    toolsDb: SonarAndToolsDatabaseBundle;
    compositeScoreA: number;
    compositeScoreB: number;
  }): Promise<SonarABComparisonResult> {
    return this.sonarService.runStandardizedABComparison(params);
  }
}
