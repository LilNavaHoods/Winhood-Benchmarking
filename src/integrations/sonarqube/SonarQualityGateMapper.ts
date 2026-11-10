import type {
  SonarQualityGateCondition,
  SonarQualityGateRecord,
} from '../../types/benchmark';

const METRIC_LABELS: Record<string, string> = {
  new_reliability_rating: 'Confiabilidade em Código Novo (Reliability Rating)',
  reliability_rating: 'Confiabilidade Geral (Reliability Rating)',
  new_security_rating: 'Segurança em Código Novo (Security Rating)',
  security_rating: 'Segurança Estática Geral (Security Rating)',
  new_maintainability_rating: 'Manutenibilidade em Código Novo (Technical Debt)',
  sqale_rating: 'Manutenibilidade Geral (Maintainability Rating)',
  new_coverage: 'Cobertura de Testes em Código Novo (%)',
  coverage: 'Cobertura de Testes Importada (%)',
  new_duplicated_lines_density: 'Densidade de Duplicação em Código Novo (%)',
  duplicated_lines_density: 'Densidade de Linhas Duplicadas (%)',
  new_security_hotspots_reviewed: 'Security Hotspots Revisados (%)',
  security_hotspots_reviewed: 'Security Hotspots Revisados (%)',
  vulnerabilities: 'Vulnerabilidades Estáticas',
  bugs: 'Bugs de Confiabilidade',
};

/**
 * SonarQualityGateMapper (Seção 6.4)
 * Importa e normaliza o resultado dos Quality Gates do SonarQube:
 * - Aprovado (OK) / Reprovado (ERROR)
 * - Condições atendidas vs não atendidas
 * - Métricas responsáveis pela reprovação
 * - Garante que as regras do Quality Gate não sejam alteradas silenciosamente entre Software A e B.
 */
export class SonarQualityGateMapper {
  public static mapProjectStatusPayload(params: {
    analysisId: string;
    projectKey: string;
    softwareId: string;
    softwareName: string;
    gateName?: string;
    projectStatus?: {
      status: 'OK' | 'ERROR' | 'WARN' | 'NONE';
      conditions?: Array<{
        status: 'OK' | 'ERROR' | 'WARN';
        metricKey: string;
        comparator: 'GT' | 'LT' | 'EQ' | 'NE';
        errorThreshold: string;
        actualValue: string;
      }>;
    };
  }): SonarQualityGateRecord {
    const status = params.projectStatus?.status || 'NONE';
    const rawConditions = params.projectStatus?.conditions || [];

    const conditions: SonarQualityGateCondition[] = rawConditions.map((c) => ({
      metricKey: c.metricKey,
      metricLabel: METRIC_LABELS[c.metricKey] || c.metricKey,
      comparator: c.comparator,
      errorThreshold: c.errorThreshold,
      actualValue: c.actualValue,
      status: c.status,
    }));

    const conditionsMetCount = conditions.filter((c) => c.status === 'OK').length;
    const failedConditions = conditions.filter((c) => c.status === 'ERROR' || c.status === 'WARN');
    const failedMetrics = failedConditions.map((c) => c.metricLabel);

    let displayLabel: SonarQualityGateRecord['displayLabel'] = 'NÃO AVALIADO';
    if (status === 'OK') displayLabel = 'APROVADO';
    else if (status === 'ERROR') displayLabel = 'REPROVADO';
    else if (status === 'WARN') displayLabel = 'ALERTA';

    return {
      id: `sqg-${params.analysisId}`,
      analysisId: params.analysisId,
      projectKey: params.projectKey,
      softwareId: params.softwareId,
      softwareName: params.softwareName,
      gateName: params.gateName || 'Sonar way (Padronizado A/B)',
      status,
      displayLabel,
      conditionsMetCount,
      conditionsFailedCount: failedConditions.length,
      failedMetrics,
      conditions,
      evaluatedAt: new Date().toISOString(),
    };
  }
}
