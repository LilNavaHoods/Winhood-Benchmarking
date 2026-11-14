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
  coverage: 'Cobertura de Testes Geral (%)',
  new_duplicated_lines_density: 'Densidade de Duplicação em Código Novo (%)',
  duplicated_lines_density: 'Densidade de Linhas Duplicadas Geral (%)',
  new_security_hotspots_reviewed: 'Security Hotspots Revisados em Código Novo (%)',
  security_hotspots_reviewed: 'Security Hotspots Revisados Geral (%)',
  vulnerabilities: 'Vulnerabilidades Estáticas (Overall)',
  new_vulnerabilities: 'Novas Vulnerabilidades (New Code)',
  bugs: 'Bugs de Confiabilidade (Overall)',
  new_bugs: 'Novos Bugs (New Code)',
  code_smells: 'Code Smells (Overall)',
  new_code_smells: 'Novos Code Smells (New Code)',
  software_quality_reliability_rating: 'MQR Reliability Rating (Overall)',
  new_software_quality_reliability_rating: 'MQR Reliability Rating (New Code)',
  software_quality_security_rating: 'MQR Security Rating (Overall)',
  new_software_quality_security_rating: 'MQR Security Rating (New Code)',
  software_quality_maintainability_rating: 'MQR Maintainability Rating (Overall)',
  new_software_quality_maintainability_rating: 'MQR Maintainability Rating (New Code)',
};

function formatComparatorText(comparator: 'GT' | 'LT' | 'EQ' | 'NE'): string {
  switch (comparator) {
    case 'GT':
      return 'maior que (>)';
    case 'LT':
      return 'menor que (<)';
    case 'EQ':
      return 'igual a (=)';
    case 'NE':
      return 'diferente de (!=)';
    default:
      return comparator;
  }
}

function buildConditionReasonText(params: {
  metricKey: string;
  metricLabel: string;
  scope: 'NEW_CODE' | 'OVERALL_CODE';
  comparator: 'GT' | 'LT' | 'EQ' | 'NE';
  errorThreshold: string;
  actualValue: string;
  status: 'OK' | 'ERROR' | 'WARN';
}): string {
  const scopeLabel = params.scope === 'NEW_CODE' ? 'New Code' : 'Overall Code';
  const compDesc = formatComparatorText(params.comparator);
  if (params.status === 'OK') {
    return `Aprovado (OK) em ${scopeLabel}: ${params.metricLabel} obteve valor ${params.actualValue} (limiar de reprovação: ${compDesc} ${params.errorThreshold}).`;
  }
  if (params.status === 'WARN') {
    return `Alerta (WARN) em ${scopeLabel}: ${params.metricLabel} obteve valor ${params.actualValue}, próximo ou no limiar ${compDesc} ${params.errorThreshold}.`;
  }
  return `Reprovado (ERROR) em ${scopeLabel}: ${params.metricLabel} obteve valor ${params.actualValue}, violando o limite (${compDesc} ${params.errorThreshold}).`;
}

/**
 * SonarQualityGateMapper (Seções 6.3, 6.4, 9.1, 9.2 e 9.3)
 * Importa e normaliza o resultado oficial dos Quality Gates do SonarQube / SonarCloud:
 * - Preserva estados reais: OK, ERROR, WARN, NONE, NOT_COMPUTED, API_ERROR
 * - Nunca presume nome do Quality Gate ("Sonar way") sem confirmação da API
 * - Distingue condições de NEW_CODE e OVERALL_CODE com explicação textual individual
 * - Identifica e documenta a aplicação do Fudge Factor em conjuntos pequenos de alterações (< 20 linhas)
 */
export class SonarQualityGateMapper {
  public static mapProjectStatusPayload(params: {
    analysisId: string;
    projectKey: string;
    softwareId: string;
    softwareName: string;
    gateName?: string | null;
    apiError?: boolean;
    apiErrorMessage?: string;
    newLinesCount?: number | null;
    newLinesToCoverCount?: number | null;
    projectStatus?: {
      status?: 'OK' | 'ERROR' | 'WARN' | 'NONE';
      ignoredConditions?: boolean;
      conditions?: Array<{
        status: 'OK' | 'ERROR' | 'WARN';
        metricKey: string;
        comparator: 'GT' | 'LT' | 'EQ' | 'NE';
        errorThreshold: string;
        actualValue: string;
      }>;
    } | null;
  }): SonarQualityGateRecord {
    const rawConditions = params.projectStatus?.conditions || [];
    const conditions: SonarQualityGateCondition[] = rawConditions.map((c) => {
      const scope: 'NEW_CODE' | 'OVERALL_CODE' = c.metricKey.startsWith('new_')
        ? 'NEW_CODE'
        : 'OVERALL_CODE';
      const metricLabel = METRIC_LABELS[c.metricKey] || c.metricKey;
      return {
        metricKey: c.metricKey,
        metricLabel,
        scope,
        comparator: c.comparator,
        errorThreshold: c.errorThreshold,
        actualValue: c.actualValue,
        status: c.status,
        reasonText: buildConditionReasonText({
          metricKey: c.metricKey,
          metricLabel,
          scope,
          comparator: c.comparator,
          errorThreshold: c.errorThreshold,
          actualValue: c.actualValue,
          status: c.status,
        }),
      };
    });

    const conditionsMetCount = conditions.filter((c) => c.status === 'OK').length;
    const failedConditions = conditions.filter(
      (c) => c.status === 'ERROR' || c.status === 'WARN'
    );
    const failedMetrics = failedConditions.map((c) => c.metricLabel);

    let status: SonarQualityGateRecord['status'] = 'NOT_COMPUTED';
    let displayLabel: SonarQualityGateRecord['displayLabel'] = 'NÃO COMPUTADO';

    if (params.apiError) {
      status = 'API_ERROR';
      displayLabel = 'ERRO DE API';
    } else if (!params.projectStatus || !params.projectStatus.status) {
      status = 'NOT_COMPUTED';
      displayLabel = 'NÃO COMPUTADO';
    } else {
      status = params.projectStatus.status;
      if (status === 'OK') displayLabel = 'APROVADO';
      else if (status === 'ERROR') displayLabel = 'REPROVADO';
      else if (status === 'WARN') displayLabel = 'ALERTA';
      else if (status === 'NONE') displayLabel = 'NÃO AVALIADO';
    }

    // Avaliar Fudge Factor (Seção 9.3: conjuntos pequenos < 20 linhas novas)
    const ignoredBySonar = params.projectStatus?.ignoredConditions === true;
    const newLines = params.newLinesCount ?? null;
    const newLinesToCover = params.newLinesToCoverCount ?? null;
    const isShortChangeset =
      ignoredBySonar ||
      (newLines !== null && newLines > 0 && newLines < 20) ||
      (newLinesToCover !== null && newLinesToCover > 0 && newLinesToCover < 20);

    let fudgeFactorStatus: SonarQualityGateRecord['fudgeFactorStatus'] = 'UNKNOWN';
    let fudgeFactorExplanation =
      'Volume de linhas novas (new_lines) não informado no payload; não é possível confirmar se o Fudge Factor de alterações curtas (< 20 linhas) foi acionado.';

    if (params.apiError) {
      fudgeFactorStatus = 'UNKNOWN';
      fudgeFactorExplanation =
        'Consulta ao endpoint /api/qualitygates/project_status falhou; estado do Fudge Factor indisponível.';
    } else if (isShortChangeset) {
      fudgeFactorStatus = 'APPLIED_SHORT_CHANGESET';
      fudgeFactorExplanation = ignoredBySonar
        ? 'O SonarCloud sinalizou ignoredConditions=true (Fudge Factor ativo): condições de cobertura e/ou duplicação em New Code foram suspensas porque o conjunto de alterações possui menos de 20 linhas.'
        : `Conjunto pequeno de alterações detectado (new_lines=${newLines ?? 'N/D'}, new_lines_to_cover=${newLinesToCover ?? 'N/D'} < 20 linhas): pela metodologia Clean as You Code do SonarCloud, condições de cobertura e duplicação em New Code podem não reprovar o Quality Gate.`;
    } else if (
      (newLines !== null && newLines >= 20) ||
      (newLinesToCover !== null && newLinesToCover >= 20) ||
      params.projectStatus?.ignoredConditions === false
    ) {
      fudgeFactorStatus = 'NOT_APPLIED';
      fudgeFactorExplanation =
        'Conjunto de alterações igual ou superior a 20 linhas (ou ignoredConditions=false); todas as condições do Quality Gate foram avaliadas integralmente sem Fudge Factor.';
    }

    // Explicação textual consolidada (Seção 9.2)
    let explanationSummary = '';
    if (status === 'API_ERROR') {
      explanationSummary = `Não foi possível obter o Quality Gate via Web API (${params.apiErrorMessage || 'erro de comunicação'}). Nenhuma aprovação é presumida.`;
    } else if (status === 'NOT_COMPUTED' || status === 'NONE') {
      explanationSummary =
        'Quality Gate ainda não computado ou não associado a esta análise no SonarQube/SonarCloud.';
    } else if (status === 'OK') {
      explanationSummary = `Quality Gate APROVADO (OK): ${conditionsMetCount} de ${conditions.length} condição(ões) atendida(s). Nota técnica: um Quality Gate aprovado sob Clean as You Code avalia prioritariamente o código novo e não garante ausência absoluta de dívida técnica ou vulnerabilidades históricas no código legado (Overall Code).`;
    } else if (status === 'WARN') {
      explanationSummary = `Quality Gate em ALERTA (WARN): ${failedConditions.length} condição(ões) exigem atenção (${failedConditions.map((c) => c.reasonText || c.metricLabel).join(' | ')}).`;
    } else {
      explanationSummary = `Quality Gate REPROVADO (ERROR): ${failedConditions.length} condição(ões) violaram os limites definidos (${failedConditions.map((c) => c.reasonText || c.metricLabel).join(' | ')}).`;
    }

    const verifiedGateName =
      typeof params.gateName === 'string' && params.gateName.trim().length > 0
        ? params.gateName.trim()
        : null;

    return {
      id: `sqg-${params.analysisId}`,
      analysisId: params.analysisId,
      projectKey: params.projectKey,
      softwareId: params.softwareId,
      softwareName: params.softwareName,
      gateName: verifiedGateName || 'NOT_VERIFIED',
      gateNameVerified: Boolean(verifiedGateName),
      status,
      displayLabel,
      conditionsMetCount,
      conditionsFailedCount: failedConditions.length,
      failedMetrics,
      conditions,
      fudgeFactorStatus,
      fudgeFactorExplanation,
      explanationSummary,
      evaluatedAt: new Date().toISOString(),
    };
  }
}
