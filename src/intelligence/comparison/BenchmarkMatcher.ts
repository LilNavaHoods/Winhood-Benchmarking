import crypto from 'node:crypto';
import type {
  BenchmarkMatchDecision,
  BenchmarkProfileConfig,
  Software,
  SoftwareScoreCard,
} from '../../types/benchmark';

export interface BenchmarkMatchInput {
  mode: BenchmarkMatchDecision['mode'];
  softwares: Software[];
  profile?: Partial<BenchmarkProfileConfig>;
  scoreCards?: SoftwareScoreCard[];
  algorithmVersion: string;
  environmentEquivalent: boolean;
  baselineAlgorithmVersion?: string;
}

function detectLanguages(sw: Software): Set<string> {
  const langs = new Set<string>();
  const extMap: Record<string, string> = {
    '.ts': 'TypeScript',
    '.tsx': 'TypeScript',
    '.js': 'JavaScript',
    '.jsx': 'JavaScript',
    '.py': 'Python',
    '.java': 'Java',
    '.cs': 'C#',
    '.go': 'Go',
    '.rs': 'Rust',
    '.sql': 'SQL',
  };
  for (const p of Object.keys(sw.sourceFilesContent || {})) {
    const idx = p.lastIndexOf('.');
    if (idx !== -1) {
      const ext = p.slice(idx).toLowerCase();
      if (extMap[ext]) langs.add(extMap[ext]);
    }
  }
  return langs;
}

function detectFrameworks(sw: Software): Set<string> {
  const frameworks = new Set<string>();
  const pkgContent = Object.entries(sw.sourceFilesContent || {}).find(([p]) =>
    p.toLowerCase().endsWith('package.json')
  )?.[1];
  if (pkgContent) {
    try {
      const parsed = JSON.parse(pkgContent);
      const deps = { ...(parsed.dependencies || {}), ...(parsed.devDependencies || {}) };
      for (const name of Object.keys(deps)) {
        if (['react', 'next', 'express', 'fastify', 'nestjs', '@nestjs/core', 'vue', 'electron'].includes(name)) {
          frameworks.add(name);
        }
      }
    } catch {
      // Ignore invalid json
    }
  }
  return frameworks;
}

/**
 * BenchmarkMatcher (P2)
 * Valida comparabilidade em 11 critérios obrigatórios antes de permitir declaração oficial de vencedor.
 */
export class BenchmarkMatcher {
  public static evaluate(input: BenchmarkMatchInput): BenchmarkMatchDecision {
    const checks: BenchmarkMatchDecision['checks'] = [];
    const blockingReasons: string[] = [];
    const warnings: string[] = [];

    const softwares = input.softwares || [];
    const multiTarget = softwares.length > 1;

    // 1. LANGUAGES
    const langSets = softwares.map(detectLanguages);
    const commonLangs =
      langSets.length > 0
        ? Array.from(langSets[0]).filter((l) => langSets.every((s) => s.has(l)))
        : [];
    const langOk = !multiTarget || commonLangs.length > 0;
    checks.push({
      criterion: 'LANGUAGES',
      passed: langOk,
      severity: langOk ? 'INFO' : 'WARNING',
      detail: langOk
        ? `Linguagens em comum: ${commonLangs.join(', ') || 'alvo único'}.`
        : 'Nenhuma linguagem primária em comum entre os alvos comparados.',
    });
    if (!langOk) {
      warnings.push('Linguagens distintas entre os softwares; interpretação comparativa requer ressalva.');
    }

    // 2. FRAMEWORKS
    const fwSets = softwares.map(detectFrameworks);
    const fwDetail = fwSets.map((s, idx) => `${softwares[idx]?.name}: ${Array.from(s).join(', ') || 'core/stdlib'}`).join(' | ');
    checks.push({
      criterion: 'FRAMEWORKS',
      passed: true,
      severity: 'INFO',
      detail: fwDetail || 'Frameworks inspecionados via manifestos.',
    });

    // 3. DOMAIN
    const domains = Array.from(new Set(softwares.map((s) => (s.functionalDomain || 'GENERAL').toUpperCase())));
    const domainCompatible =
      !multiTarget ||
      domains.length <= 1 ||
      domains.every((d) => ['PASSWORD_MANAGER', 'SECRETS_VAULT', 'PASSWORD_SECURITY_VAULT'].includes(d)) ||
      domains.every((d) => ['API_SERVICE', 'MICROSERVICES', 'WEB_APP'].includes(d));
    checks.push({
      criterion: 'DOMAIN',
      passed: domainCompatible,
      severity: domainCompatible ? 'INFO' : 'BLOCKING',
      detail: domainCompatible
        ? `Domínio(s) compatível(is): ${domains.join(', ')}.`
        : `Domínios incompatíveis (${domains.join(' vs ')}): comparação direta inválida.`,
    });
    if (!domainCompatible) {
      blockingReasons.push(`Domínios funcionais incompatíveis: ${domains.join(' vs ')}.`);
    }

    // 4. SCOPE
    const enabledCats = input.profile?.enabledCategories || [];
    const scopeOk = enabledCats.length > 0;
    checks.push({
      criterion: 'SCOPE',
      passed: scopeOk,
      severity: scopeOk ? 'INFO' : 'BLOCKING',
      detail: scopeOk
        ? `${enabledCats.length} categoria(s) habilitada(s) igualmente para todos os alvos.`
        : 'Nenhuma categoria habilitada no escopo.',
    });
    if (!scopeOk) blockingReasons.push('Escopo de avaliação vazio.');

    // 5. COMMIT_BASELINE
    const missingCommit = softwares.filter((s) => !s.commitHash || s.commitHash.length < 7);
    const commitOk = missingCommit.length === 0;
    checks.push({
      criterion: 'COMMIT_BASELINE',
      passed: commitOk,
      severity: commitOk ? 'INFO' : 'WARNING',
      detail: commitOk
        ? 'Todos os alvos possuem commitHash / baseline versionado registrado.'
        : `${missingCommit.map((s) => s.name).join(', ')} sem commitHash explícito (comparação por snapshot de upload).`,
    });
    if (!commitOk) {
      warnings.push(`Commit baseline ausente para: ${missingCommit.map((s) => s.name).join(', ')}.`);
    }

    // 6. ENGINE_VERSIONS
    const engineMatch =
      !input.baselineAlgorithmVersion || input.baselineAlgorithmVersion === input.algorithmVersion;
    checks.push({
      criterion: 'ENGINE_VERSIONS',
      passed: engineMatch,
      severity: engineMatch ? 'INFO' : 'BLOCKING',
      detail: engineMatch
        ? `Versão do motor consistente (${input.algorithmVersion}).`
        : `Versão divergente (${input.algorithmVersion} vs ${input.baselineAlgorithmVersion}).`,
    });
    if (!engineMatch) blockingReasons.push('Versão do algoritmo diverge entre baseline e execução atual.');

    // 7. QUALITY_PROFILES
    const qp = input.profile?.qualityProfileIds || ['qp-sonar-way-ts'];
    checks.push({
      criterion: 'QUALITY_PROFILES',
      passed: qp.length > 0,
      severity: 'INFO',
      detail: `Quality Profiles aplicados uniformemente: ${qp.join(', ')}.`,
    });

    // 8. QUALITY_GATES
    const qg = input.profile?.qualityGateId || 'qg-sonar-way';
    checks.push({
      criterion: 'QUALITY_GATES',
      passed: Boolean(qg),
      severity: 'INFO',
      detail: `Quality Gate compartilhado: ${qg}.`,
    });

    // 9. AVAILABLE_REPORTS (Source & Coverage symmetry)
    const eligibleFlags = softwares.map(
      (s) =>
        s.sourceType !== 'PUBLIC_DOCUMENTATION_ONLY' &&
        s.sourceAvailability !== 'PUBLIC_DOCUMENTATION_ONLY' &&
        s.sourceAvailability !== 'CLOSED_SOURCE' &&
        Object.keys(s.sourceFilesContent || {}).length > 0
    );
    const hasIneligible = eligibleFlags.some((f) => !f);
    const reportsSymmetric = !hasIneligible;
    checks.push({
      criterion: 'AVAILABLE_REPORTS',
      passed: reportsSymmetric,
      severity: reportsSymmetric ? 'INFO' : 'BLOCKING',
      detail: reportsSymmetric
        ? 'Todos os alvos possuem artefatos de código-fonte elegíveis e inventário verificado.'
        : 'Ao menos um software não possui código-fonte elegível completo (ex.: documentação pública ou metadados apenas).',
    });
    if (!reportsSymmetric) {
      blockingReasons.push('Assimetria de disponibilidade de código-fonte/relatórios entre os softwares.');
    }

    // 10. EXECUTION_ENVIRONMENT
    const envOk = input.environmentEquivalent || !multiTarget;
    checks.push({
      criterion: 'EXECUTION_ENVIRONMENT',
      passed: envOk,
      severity: envOk ? 'INFO' : 'BLOCKING',
      detail: envOk
        ? 'Ambiente experimental e limites de recursos equivalentes.'
        : 'Ambiente experimental não equivalente entre os alvos.',
    });
    if (!envOk) blockingReasons.push('Limites de hardware/ambiente experimental não equivalentes.');

    // 11. TEST_COVERAGE
    const covList = (input.scoreCards || []).map((sc) => ({
      name: sc.softwareName,
      cov: sc.metricsSummary.testCoveragePercent,
    }));
    const measuredCovs = covList.filter((c): c is { name: string; cov: number } => typeof c.cov === 'number');
    const unmeasuredOrZero = covList.filter((c) => c.cov === null || c.cov === 0);
    const covMismatch =
      multiTarget &&
      covList.length >= 2 &&
      measuredCovs.some((c) => c.cov > 0) &&
      unmeasuredOrZero.length > 0;
    checks.push({
      criterion: 'TEST_COVERAGE',
      passed: !covMismatch,
      severity: covMismatch ? 'BLOCKING' : 'INFO',
      detail: covMismatch
        ? `Assimetria de relatórios reais de cobertura (${covList.map((c) => `${c.name}: ${c.cov === null ? 'NOT_MEASURED' : `${c.cov}%`}`).join(' vs ')}).`
        : `Simetria de relatórios de cobertura verificada (${covList.map((c) => `${c.name}: ${c.cov === null ? 'NOT_MEASURED' : `${c.cov}%`}`).join(' vs ') || 'aguardando scorecard'}).`,
    });
    if (covMismatch) {
      blockingReasons.push(
        'Assimetria de cobertura de testes: um alvo possui relatório real medido e outro está NOT_MEASURED / 0%.'
      );
      warnings.push('Um dos alvos possui relatório real de cobertura (LCOV/JaCoCo) e o outro não (NOT_MEASURED).');
    }

    const passedCount = checks.filter((c) => c.passed).length;
    const compatibilityScorePercent = Math.round((passedCount / checks.length) * 100);
    const comparable = blockingReasons.length === 0;
    const canDeclareOfficialWinner = comparable && (input.mode === 'INDIVIDUAL' || softwares.length > 1);

    return {
      matchId: `match-${crypto.createHash('sha256').update(`${input.mode}:${softwares.map((s) => s.id).join('|')}`).digest('hex').slice(0, 12)}`,
      mode: input.mode,
      comparable,
      canDeclareOfficialWinner,
      compatibilityScorePercent,
      checks,
      blockingReasons,
      warnings,
    };
  }
}
