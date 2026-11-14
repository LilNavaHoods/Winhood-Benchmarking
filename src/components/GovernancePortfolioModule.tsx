import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { csrfFetch as fetch } from '../utils/csrfFetch';
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  Code2,
  Copy,
  Download,
  FileCode2,
  GitPullRequest,
  KeyRound,
  Layers,
  Plus,
  RefreshCw,
  Scale,
  Search,
  ShieldAlert,
  ShieldCheck,
  TrendingDown,
  TrendingUp,
  Webhook,
} from 'lucide-react';
import type { BenchmarkRun, Software } from '../types/benchmark';

interface GovernancePortfolioModuleProps {
  latestRun: BenchmarkRun | null;
  softwares: Software[];
  onNotify: (msg: string, type?: 'success' | 'error') => void;
}

interface QualityGateConditionRule {
  id: string;
  metricKey: string;
  label: string;
  operator: 'LT' | 'LTE' | 'GT' | 'GTE' | 'EQ';
  threshold: number;
  severityOnFail: 'BLOCKER' | 'RESERVATION';
}

interface QualityGateDefinition {
  id: string;
  name: string;
  version: string;
  description: string;
  requireVerifiedEvidence: boolean;
  createdAt: string;
  gateHash?: string;
  conditions: QualityGateConditionRule[];
}

interface GateEvaluationResult {
  gateId: string;
  gateName: string;
  gateVersion: string;
  gateHash: string;
  decision: 'APPROVED' | 'APPROVED_WITH_RESERVATIONS' | 'BLOCKED' | 'INCONCLUSIVE' | 'REJECTED';
  cliExitCode: 0 | 1 | 2;
  evaluatedAt: string;
  conditionsMet: number;
  conditionsFailed: number;
  conditionsInconclusive: number;
  summary: string;
  conditions: Array<{
    id: string;
    metricKey: string;
    label: string;
    operator: string;
    threshold: number;
    actualValue: number | null;
    passed: boolean;
    inconclusive: boolean;
    severityOnFail: 'BLOCKER' | 'RESERVATION';
    reason: string;
  }>;
}

interface PortfolioSummary {
  generatedAt: string;
  totalProjects: number;
  totalSoftwares: number;
  totalRuns: number;
  verifiedRunsCount: number;
  verifiedRunsRatePercent: number | null;
  avgScopeCoveragePercent: number | null;
  totalTechnicalDebtMinutes: number;
  confidenceDistribution: {
    HIGH: number;
    MEDIUM: number;
    LOW: number;
  };
  findingTrends: Array<{
    runId: string;
    label: string;
    completedAt: string;
    blockerOrCritical: number;
    high: number;
    mediumOrLow: number;
    total: number;
    technicalDebtMinutes: number;
  }>;
  releaseProgression: Array<{
    runId: string;
    projectId: string;
    projectName: string;
    softwareId: string;
    softwareName: string;
    softwareVersion: string;
    completedAt: string;
    overallScore: number | null;
    totalFindings: number;
    criticalOrBlockerFindings: number;
    highFindings: number;
    technicalDebtMinutes: number;
    scopeCoveragePercent: number;
    uncoveredCategoriesCount: number;
    evidenceConfidence: 'HIGH' | 'MEDIUM' | 'LOW';
    gateDecision: string;
    evidenceVerified: boolean;
    deltaFindingsFromPrevious: number | null;
    deltaScoreFromPrevious: number | null;
  }>;
  uncoveredDimensionsSummary: Array<{
    category: string;
    unmeasuredRunsCount: number;
  }>;
}

type ComplianceFrameworkKey =
  | 'OWASP_TOP_10_2021'
  | 'CWE_TOP_25'
  | 'PCI_DSS_V4'
  | 'ISO_27001_2022';

interface ComplianceControlMappingEntry {
  framework: ComplianceFrameworkKey;
  controlId: string;
  controlTitle: string;
  status: 'FINDINGS_DETECTED' | 'NO_FINDINGS_IN_ANALYZED_SCOPE';
  findingsCount: number;
  criticalOrBlockerCount: number;
  matchedCwes: string[];
  evidenceFindingIds: string[];
}

interface ComplianceTraceabilityMatrix {
  generatedAt: string;
  runId: string;
  disclaimer: string;
  scopeNotes: string[];
  totalFindingsMapped: number;
  byFramework: Record<ComplianceFrameworkKey, ComplianceControlMappingEntry[]>;
}

interface RuleCatalogEntry {
  ruleId: string;
  title: string;
  severity: string;
  category: string;
  languages: string[];
  cwe?: string;
  owaspTop10?: string;
  cweTop25Rank?: number;
  cvssBase?: number;
  version: string;
  sinceEngineVersion: string;
  deprecated?: boolean;
  remediation: string;
  positiveExamples?: string[];
  negativeExamples?: string[];
}

interface RulesCatalogResponse {
  engineVersion: string;
  semverPolicy: string;
  catalogSha256: string;
  totalRules: number;
  rules: RuleCatalogEntry[];
  plugins: Array<{
    id: string;
    name: string;
    version: string;
    supportedLanguages: string[];
    capabilities: string[];
  }>;
}

interface SecretsCatalogResponse {
  version: string;
  patternsCount: number;
  checksumSha256: string;
  documentedExclusions: string[];
  patterns: Array<{
    patternId: string;
    ruleId: string;
    name: string;
    version: string;
    severity: string;
    cwe: string;
    owaspTop10: string;
    cvssBase: number;
    minShannonEntropy: number;
    supportsOptionalValidation: boolean;
    validationMethod: string;
    falsePositiveExclusions: string[];
  }>;
}

type GovernanceSubTab = 'gates' | 'portfolio' | 'compliance' | 'catalog';

const FRAMEWORK_LABELS: Record<ComplianceFrameworkKey, string> = {
  OWASP_TOP_10_2021: 'OWASP Top 10 (2021)',
  CWE_TOP_25: 'CWE Top 25',
  PCI_DSS_V4: 'PCI DSS v4.0 (Rastreabilidade)',
  ISO_27001_2022: 'ISO/IEC 27001:2022 (Rastreabilidade)',
};

export const GovernancePortfolioModule: React.FC<GovernancePortfolioModuleProps> = ({
  latestRun,
  onNotify,
}) => {
  const [subTab, setSubTab] = useState<GovernanceSubTab>('gates');

  // Gates & Webhooks state
  const [gates, setGates] = useState<QualityGateDefinition[]>([]);
  const [selectedGateId, setSelectedGateId] = useState<string>('winhood-standard-v2');
  const [gateResult, setGateResult] = useState<GateEvaluationResult | null>(null);
  const [gateLoading, setGateLoading] = useState<boolean>(false);

  // Create custom gate form
  const [showCreateGate, setShowCreateGate] = useState<boolean>(false);
  const [newGateId, setNewGateId] = useState<string>('');
  const [newGateName, setNewGateName] = useState<string>('');
  const [newGateVersion, setNewGateVersion] = useState<string>('1.0.0');
  const [newGateMaxCritical, setNewGateMaxCritical] = useState<number>(0);
  const [newGateMinCoverage, setNewGateMinCoverage] = useState<number>(75);

  // Signed webhook test + PR/MR decoration preview
  const [webhookUrl, setWebhookUrl] = useState<string>('');
  const [webhookPreview, setWebhookPreview] = useState<{
    mode: string;
    signatureHeader: string;
    keyId: string;
    payloadSha256: string;
    decision: string;
  } | null>(null);
  const [prProvider, setPrProvider] = useState<'GITHUB' | 'GITLAB' | 'JENKINS'>('GITHUB');
  const [prMarkdown, setPrMarkdown] = useState<string | null>(null);

  // Portfolio state
  const [portfolio, setPortfolio] = useState<PortfolioSummary | null>(null);
  const [portfolioLoading, setPortfolioLoading] = useState<boolean>(false);

  // Compliance state
  const [compliance, setCompliance] = useState<ComplianceTraceabilityMatrix | null>(null);
  const [selectedFramework, setSelectedFramework] =
    useState<ComplianceFrameworkKey>('OWASP_TOP_10_2021');
  const [complianceLoading, setComplianceLoading] = useState<boolean>(false);

  // Catalog & OpenAPI state
  const [rulesCatalog, setRulesCatalog] = useState<RulesCatalogResponse | null>(null);
  const [secretsCatalog, setSecretsCatalog] = useState<SecretsCatalogResponse | null>(null);
  const [catalogSearch, setCatalogSearch] = useState<string>('');
  const [expandedRuleId, setExpandedRuleId] = useState<string | null>(null);
  const [openApiSummary, setOpenApiSummary] = useState<{
    version: string;
    title: string;
    pathCount: number;
    paths: string[];
  } | null>(null);

  const loadGates = useCallback(async () => {
    try {
      const res = await fetch('/api/quality-gates');
      if (res.ok) {
        const data = (await res.json()) as { gates?: QualityGateDefinition[] };
        if (Array.isArray(data.gates)) {
          setGates(data.gates);
        }
      }
    } catch {
      // Handled gracefully by empty state
    }
  }, []);

  const loadPortfolio = useCallback(async () => {
    setPortfolioLoading(true);
    try {
      const res = await fetch('/api/portfolio/summary');
      if (res.ok) {
        const data = (await res.json()) as { summary?: PortfolioSummary };
        if (data.summary) setPortfolio(data.summary);
      }
    } catch {
      onNotify('Falha ao carregar resumo de portfólio.', 'error');
    } finally {
      setPortfolioLoading(false);
    }
  }, [onNotify]);

  const loadCompliance = useCallback(async () => {
    if (!latestRun) return;
    setComplianceLoading(true);
    try {
      const res = await fetch(`/api/compliance/${encodeURIComponent(latestRun.id)}/matrix`);
      if (res.ok) {
        const data = (await res.json()) as { matrix?: ComplianceTraceabilityMatrix };
        if (data.matrix) setCompliance(data.matrix);
      }
    } catch {
      onNotify('Falha ao gerar matriz de rastreabilidade de conformidade.', 'error');
    } finally {
      setComplianceLoading(false);
    }
  }, [latestRun, onNotify]);

  const loadCatalogs = useCallback(async () => {
    try {
      const [rulesRes, secretsRes, apiRes] = await Promise.all([
        fetch('/api/rules/catalog'),
        fetch('/api/secrets/catalog'),
        fetch('/api/openapi.json'),
      ]);
      if (rulesRes.ok) {
        setRulesCatalog((await rulesRes.json()) as RulesCatalogResponse);
      }
      if (secretsRes.ok) {
        setSecretsCatalog((await secretsRes.json()) as SecretsCatalogResponse);
      }
      if (apiRes.ok) {
        const spec = (await apiRes.json()) as {
          info?: { version?: string; title?: string };
          paths?: Record<string, unknown>;
        };
        const paths = Object.keys(spec.paths || {});
        setOpenApiSummary({
          version: spec.info?.version || '4.3.0',
          title: spec.info?.title || 'WinHood Audit & Benchmarking API',
          pathCount: paths.length,
          paths,
        });
      }
    } catch {
      onNotify('Falha ao carregar catálogos públicos ou OpenAPI.', 'error');
    }
  }, [onNotify]);

  useEffect(() => {
    void loadGates();
  }, [loadGates]);

  useEffect(() => {
    if (subTab === 'portfolio' && !portfolio) {
      void loadPortfolio();
    } else if (subTab === 'compliance' && latestRun && compliance?.runId !== latestRun.id) {
      void loadCompliance();
    } else if (subTab === 'catalog' && !rulesCatalog) {
      void loadCatalogs();
    }
  }, [
    subTab,
    portfolio,
    compliance,
    latestRun,
    rulesCatalog,
    loadPortfolio,
    loadCompliance,
    loadCatalogs,
  ]);

  const handleEvaluateGate = async () => {
    if (!latestRun) {
      onNotify('Execute um benchmark antes de avaliar um Quality Gate.', 'error');
      return;
    }
    setGateLoading(true);
    try {
      const res = await fetch('/api/quality-gates/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          runId: latestRun.id,
          gateId: selectedGateId,
        }),
      });
      const data = (await res.json()) as { evaluation?: GateEvaluationResult; error?: string };
      if (!res.ok || !data.evaluation) {
        onNotify(data.error || 'Falha ao avaliar Quality Gate.', 'error');
        return;
      }
      setGateResult(data.evaluation);
      onNotify(
        `Quality Gate ${data.evaluation.gateName} v${data.evaluation.gateVersion}: ${data.evaluation.decision}`,
        'success'
      );
    } catch {
      onNotify('Erro de comunicação ao avaliar Quality Gate.', 'error');
    } finally {
      setGateLoading(false);
    }
  };

  const handleCreateCustomGate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newGateId.trim() || !newGateName.trim()) {
      onNotify('Informe ID e Nome do novo Quality Gate.', 'error');
      return;
    }
    try {
      const res = await fetch('/api/quality-gates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: newGateId.trim(),
          name: newGateName.trim(),
          version: newGateVersion.trim() || '1.0.0',
          description: 'Gate customizado criado via Governança WinHood.',
          requireVerifiedEvidence: true,
          conditions: [
            {
              id: 'custom-critical-max',
              metricKey: 'critical_findings',
              label: `Máximo de ${newGateMaxCritical} achados críticos`,
              operator: 'LTE',
              threshold: Number(newGateMaxCritical),
              severityOnFail: 'BLOCKER',
            },
            {
              id: 'custom-scope-cov',
              metricKey: 'scope_coverage_percent',
              label: `Cobertura mínima de escopo >= ${newGateMinCoverage}%`,
              operator: 'GTE',
              threshold: Number(newGateMinCoverage),
              severityOnFail: 'BLOCKER',
            },
          ],
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || 'Erro ao salvar Quality Gate customizado.', 'error');
        return;
      }
      await loadGates();
      setSelectedGateId(data.gate?.id || newGateId.trim());
      setShowCreateGate(false);
      setNewGateId('');
      setNewGateName('');
      onNotify('Quality Gate versionado salvo com sucesso.', 'success');
    } catch {
      onNotify('Erro ao cadastrar Quality Gate.', 'error');
    }
  };

  const handleTestWebhookSignature = async () => {
    if (!latestRun) {
      onNotify('Execute um benchmark para assinar um payload de gate real.', 'error');
      return;
    }
    try {
      const res = await fetch('/api/webhooks/sign-test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          runId: latestRun.id,
          gateId: selectedGateId,
          targetUrl: webhookUrl.trim() || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        onNotify(data.dispatchResult?.error || data.error || 'Falha ao assinar webhook.', 'error');
        return;
      }
      if (data.mode === 'SIGNED_PREVIEW' && data.signedPayload) {
        setWebhookPreview({
          mode: data.mode,
          signatureHeader: data.signedPayload.signatureHeader,
          keyId: data.signedPayload.keyId,
          payloadSha256: data.signedPayload.payloadSha256,
          decision: data.evaluation?.decision || 'EVALUATED',
        });
        onNotify('Assinatura HMAC-SHA256 do webhook gerada localmente com sucesso.', 'success');
      } else if (data.dispatchResult) {
        setWebhookPreview({
          mode: `DISPATCHED (HTTP ${data.dispatchResult.statusCode ?? 'N/A'})`,
          signatureHeader: data.dispatchResult.signatureHeader || '',
          keyId: 'hmac-kms',
          payloadSha256: data.dispatchResult.delivered ? 'DELIVERED' : data.dispatchResult.error || 'FAILED',
          decision: data.evaluation?.decision || 'EVALUATED',
        });
        onNotify(
          data.dispatchResult.delivered
            ? 'Webhook assinado entregue com sucesso.'
            : `Envio bloqueado/recusado: ${data.dispatchResult.error || 'erro de rede'}`,
          data.dispatchResult.delivered ? 'success' : 'error'
        );
      }
    } catch {
      onNotify('Erro ao testar assinatura de webhook.', 'error');
    }
  };

  const handleGeneratePrDecoration = async () => {
    if (!latestRun) return;
    try {
      const res = await fetch('/api/integrations/pr-decoration', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          runId: latestRun.id,
          gateId: selectedGateId,
          provider: prProvider,
          repository: latestRun.projectName || 'org/repo',
        }),
      });
      const data = (await res.json()) as {
        decoration?: { markdownComment?: string };
        error?: string;
      };
      if (!res.ok || !data.decoration) {
        onNotify(data.error || 'Erro ao gerar PR/MR decoration.', 'error');
        return;
      }
      setPrMarkdown(data.decoration.markdownComment || '');
      onNotify(`Comentário PR/MR (${prProvider}) gerado com decisão e manifesto.`, 'success');
    } catch {
      onNotify('Erro ao gerar preview de PR/MR.', 'error');
    }
  };

  const filteredRules = useMemo(() => {
    if (!rulesCatalog) return [];
    const q = catalogSearch.trim().toLowerCase();
    if (!q) return rulesCatalog.rules;
    return rulesCatalog.rules.filter(
      (r) =>
        r.ruleId.toLowerCase().includes(q) ||
        r.title.toLowerCase().includes(q) ||
        (r.cwe || '').toLowerCase().includes(q) ||
        (r.owaspTop10 || '').toLowerCase().includes(q) ||
        r.languages.some((l) => l.toLowerCase().includes(q))
    );
  }, [rulesCatalog, catalogSearch]);

  const activeFrameworkControls = useMemo(() => {
    if (!compliance) return [];
    return compliance.byFramework?.[selectedFramework] || [];
  }, [compliance, selectedFramework]);

  const decisionBadgeClass = (decision: string) => {
    if (decision === 'APPROVED') return 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30';
    if (decision === 'APPROVED_WITH_RESERVATIONS')
      return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    if (decision === 'INCONCLUSIVE') return 'bg-sky-500/15 text-sky-400 border-sky-500/30';
    return 'bg-rose-500/15 text-rose-500 border-rose-500/30';
  };

  return (
    <div className="space-y-6">
      {/* Header & Sub-Tabs */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2.5">
            <Scale className="w-6 h-6 text-[#31d6c4]" />
            <span>Governança, Quality Gates, Portfólio &amp; Rastreabilidade</span>
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            Camada independente de auditoria baseada em padrões abertos (SARIF 2.1.0, CWE, OWASP Top 10, CVSS, CycloneDX 1.5, SPDX 2.3).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-1 p-1 rounded-lg bg-slate-200/70 dark:bg-[#0f141c] border border-slate-300/60 dark:border-slate-800 shrink-0">
          {[
            { id: 'gates', label: 'Quality Gates & Webhooks' },
            { id: 'portfolio', label: 'Portfólio & Releases' },
            { id: 'compliance', label: 'Matriz Conformidade' },
            { id: 'catalog', label: 'Catálogo Regras & OpenAPI' },
          ].map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setSubTab(t.id as GovernanceSubTab)}
              className={`px-3.5 py-1.5 rounded-md text-xs font-semibold transition-colors whitespace-nowrap cursor-pointer ${
                subTab === t.id
                  ? 'bg-[#31d6c4] text-slate-950'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* SUB-TAB 1: QUALITY GATES, SIGNED WEBHOOKS & PR/MR DECORATION */}
      {subTab === 'gates' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left: Versioned Gate Selection & Custom Gate Creation */}
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
                <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-[#31d6c4]" />
                  <span>Quality Gates Versionados ({gates.length})</span>
                </h2>
                <button
                  type="button"
                  onClick={() => setShowCreateGate((v) => !v)}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-xs font-semibold border border-[#31d6c4]/40 text-[#0e9f8e] dark:text-[#31d6c4] hover:bg-[#31d6c4]/10 cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Novo Gate</span>
                </button>
              </div>

              {showCreateGate && (
                <form
                  onSubmit={handleCreateCustomGate}
                  className="p-3.5 rounded-lg border border-[#31d6c4]/30 bg-[#31d6c4]/5 space-y-2.5 text-xs"
                >
                  <div className="font-bold text-slate-900 dark:text-slate-100">
                    Cadastrar Quality Gate Customizado
                  </div>
                  <input
                    type="text"
                    placeholder="ID estável (ex.: finops-strict-v1)"
                    value={newGateId}
                    onChange={(e) => setNewGateId(e.target.value)}
                    className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 font-mono text-xs"
                  />
                  <input
                    type="text"
                    placeholder="Nome do Gate"
                    value={newGateName}
                    onChange={(e) => setNewGateName(e.target.value)}
                    className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2.5 py-1.5 text-xs"
                  />
                  <div className="grid grid-cols-3 gap-2">
                    <label className="block">
                      <span className="text-[10px] text-slate-500">Versão</span>
                      <input
                        type="text"
                        value={newGateVersion}
                        onChange={(e) => setNewGateVersion(e.target.value)}
                        className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2 py-1 font-mono text-xs"
                      />
                    </label>
                    <label className="block">
                      <span className="text-[10px] text-slate-500">Máx. Críticos</span>
                      <input
                        type="number"
                        min={0}
                        value={newGateMaxCritical}
                        onChange={(e) => setNewGateMaxCritical(Number(e.target.value))}
                        className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2 py-1 font-mono text-xs"
                      />
                    </label>
                    <label className="block">
                      <span className="text-[10px] text-slate-500">Escopo Mín %</span>
                      <input
                        type="number"
                        min={0}
                        max={100}
                        value={newGateMinCoverage}
                        onChange={(e) => setNewGateMinCoverage(Number(e.target.value))}
                        className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#080b10] px-2 py-1 font-mono text-xs"
                      />
                    </label>
                  </div>
                  <div className="flex justify-end gap-2">
                    <button
                      type="button"
                      onClick={() => setShowCreateGate(false)}
                      className="px-2.5 py-1 rounded border border-slate-300 dark:border-slate-700 text-xs cursor-pointer"
                    >
                      Cancelar
                    </button>
                    <button
                      type="submit"
                      className="px-3 py-1 rounded bg-[#31d6c4] text-slate-950 font-bold text-xs cursor-pointer"
                    >
                      Salvar Gate
                    </button>
                  </div>
                </form>
              )}

              <div className="space-y-2.5">
                {gates.map((g) => {
                  const active = g.id === selectedGateId;
                  return (
                    <button
                      key={g.id}
                      type="button"
                      onClick={() => setSelectedGateId(g.id)}
                      className={`w-full text-left p-3 rounded-lg border transition-colors cursor-pointer space-y-1 ${
                        active
                          ? 'border-[#31d6c4] bg-[#31d6c4]/10'
                          : 'border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#080b10] hover:border-slate-300 dark:hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                          {g.name}
                        </span>
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-[#0e9f8e] dark:text-[#31d6c4]">
                          v{g.version}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500">{g.description}</p>
                      <div className="font-mono text-[10px] text-slate-400">
                        {g.conditions.length} condições booleanas ·{' '}
                        {g.requireVerifiedEvidence ? 'EVIDÊNCIA VERIFICADA' : 'STANDARD'}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Right 2 cols: Live Evaluation & CLI Exit Codes */}
            <div className="lg:col-span-2 space-y-6">
              <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                      Avaliação Acionável do Quality Gate (CI/CD &amp; CLI Exit Codes)
                    </h3>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Exit codes padronizados: <code>0 = APPROVED / RESERVATIONS</code>, <code>1 = BLOCKED / REJECTED</code>, <code>2 = INCONCLUSIVE</code>, <code>3 = RUNTIME_ERROR</code>.
                    </p>
                  </div>
                  <button
                    type="button"
                    disabled={!latestRun || gateLoading}
                    onClick={() => void handleEvaluateGate()}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] disabled:opacity-50 cursor-pointer"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${gateLoading ? 'animate-spin' : ''}`} />
                    <span>{gateLoading ? 'Avaliando...' : 'Avaliar Gate na Execução Atual'}</span>
                  </button>
                </div>

                {!latestRun ? (
                  <div className="p-6 rounded-lg border border-dashed border-slate-300 dark:border-slate-700 text-center text-xs text-slate-500">
                    Nenhuma execução disponível ainda. Carregue ou execute um benchmark no Wizard para avaliar o Quality Gate.
                  </div>
                ) : gateResult ? (
                  <div className="space-y-4">
                    <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] flex flex-wrap items-center justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2.5 py-0.5 rounded border font-mono text-xs font-bold ${decisionBadgeClass(gateResult.decision)}`}
                          >
                            {gateResult.decision}
                          </span>
                          <span className="font-mono text-xs text-slate-500">
                            CLI Exit Code:{' '}
                            <strong className="text-slate-900 dark:text-slate-100">
                              {gateResult.cliExitCode}
                            </strong>
                          </span>
                        </div>
                        <div className="font-mono text-[11px] text-slate-400">
                          Gate: {gateResult.gateName} v{gateResult.gateVersion} · Hash:{' '}
                          <span className="text-[#31d6c4]">
                            {gateResult.gateHash.slice(0, 16)}...
                          </span>
                        </div>
                        <div className="text-xs text-slate-600 dark:text-slate-300">
                          {gateResult.summary}
                        </div>
                      </div>
                      <div className="text-right font-mono text-[11px] text-slate-400">
                        {new Date(gateResult.evaluatedAt).toLocaleString('pt-BR')}
                      </div>
                    </div>

                    <div className="overflow-x-auto">
                      <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                        <thead>
                          <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                            <th className="py-2 pr-3">Condição</th>
                            <th className="py-2 px-3">Métrica</th>
                            <th className="py-2 px-3">Observado</th>
                            <th className="py-2 px-3">Regra</th>
                            <th className="py-2 pl-3">Estado</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                          {gateResult.conditions.map((c) => (
                            <tr key={c.id}>
                              <td className="py-2 pr-3 font-sans text-slate-800 dark:text-slate-200">
                                {c.label}
                              </td>
                              <td className="py-2 px-3 text-[#31d6c4]">{c.metricKey}</td>
                              <td className="py-2 px-3 font-bold">
                                {c.actualValue === null ? 'NOT_MEASURED' : String(c.actualValue)}
                              </td>
                              <td className="py-2 px-3 text-slate-400">
                                {c.operator} {c.threshold} ({c.severityOnFail})
                              </td>
                              <td className="py-2 pl-3 font-bold">
                                <span
                                  className={
                                    c.inconclusive
                                      ? 'text-sky-400'
                                      : c.passed
                                        ? 'text-emerald-500'
                                        : 'text-rose-500'
                                  }
                                >
                                  {c.inconclusive ? 'INCONCLUSIVE' : c.passed ? 'PASS' : 'FAIL'}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ) : (
                  <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-[#080b10] text-xs text-slate-500">
                    Clique em <strong>&quot;Avaliar Gate na Execução Atual&quot;</strong> para computar todas as condições booleanas do gate selecionado sobre a corrida <code>{latestRun.id}</code>.
                  </div>
                )}
              </div>

              {/* Signed Webhook & PR/MR Decoration Row */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-3">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                    <Webhook className="w-4 h-4 text-[#31d6c4]" />
                    <span>Webhook Assinado HMAC-SHA256 (SSRF-Protected)</span>
                  </h3>
                  <p className="text-xs text-slate-500">
                    Deixe a URL vazia para gerar preview local assinado (<code>X-WinHood-Signature</code>) ou informe um endpoint HTTPS autorizado pelo SsrfGuard.
                  </p>
                  <input
                    type="url"
                    aria-label="URL de destino do Webhook (opcional)"
                    placeholder="Opcional: https://hooks.empresa.com/winhood"
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                    className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 font-mono text-xs"
                  />
                  <button
                    type="button"
                    disabled={!latestRun}
                    onClick={() => void handleTestWebhookSignature()}
                    className="w-full px-3 py-2 rounded-lg text-xs font-semibold border border-[#31d6c4]/40 bg-[#31d6c4]/10 text-[#0e9f8e] dark:text-[#31d6c4] hover:bg-[#31d6c4]/20 disabled:opacity-50 cursor-pointer"
                  >
                    {webhookUrl.trim() ? 'Assinar & Disparar Webhook' : 'Gerar Preview Assinado Localmente'}
                  </button>
                  {webhookPreview && (
                    <div className="p-2.5 rounded border border-emerald-500/30 bg-emerald-500/5 font-mono text-[10px] space-y-1 break-all">
                      <div className="text-emerald-500 font-bold">
                        Modo: {webhookPreview.mode} · Decisão: {webhookPreview.decision}
                      </div>
                      <div className="text-slate-400">
                        X-WinHood-Signature: {webhookPreview.signatureHeader}
                      </div>
                      <div className="text-slate-400">
                        Payload SHA-256: {webhookPreview.payloadSha256}
                      </div>
                    </div>
                  )}
                </div>

                <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-3">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                    <GitPullRequest className="w-4 h-4 text-[#31d6c4]" />
                    <span>PR / MR Decoration (GitHub, GitLab &amp; Jenkins)</span>
                  </h3>
                  <div className="flex items-center gap-2">
                    <select
                      aria-label="Provedor de CI/CD para PR Decoration"
                      value={prProvider}
                      onChange={(e) =>
                        setPrProvider(e.target.value as 'GITHUB' | 'GITLAB' | 'JENKINS')
                      }
                      className="flex-1 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-2.5 py-1.5 text-xs font-mono"
                    >
                      <option value="GITHUB">GitHub Pull Request</option>
                      <option value="GITLAB">GitLab Merge Request</option>
                      <option value="JENKINS">Jenkins Pipeline Summary</option>
                    </select>
                    <button
                      type="button"
                      disabled={!latestRun}
                      onClick={() => void handleGeneratePrDecoration()}
                      className="px-3 py-1.5 rounded-lg text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] disabled:opacity-50 cursor-pointer"
                    >
                      Gerar Comentário
                    </button>
                  </div>
                  {prMarkdown && (
                    <div className="space-y-1.5">
                      <div className="flex justify-end">
                        <button
                          type="button"
                          onClick={() => {
                            void navigator.clipboard.writeText(prMarkdown);
                            onNotify('Markdown de PR/MR copiado para a área de transferência.', 'success');
                          }}
                          className="inline-flex items-center gap-1 text-[11px] text-[#31d6c4] hover:underline cursor-pointer"
                        >
                          <Copy className="w-3 h-3" />
                          <span>Copiar Markdown</span>
                        </button>
                      </div>
                      <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-slate-200 max-h-40 overflow-y-auto whitespace-pre-wrap">
                        {prMarkdown}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 2: PORTFOLIO & RELEASE PROGRESSION */}
      {subTab === 'portfolio' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Layers className="w-4 h-4 text-[#31d6c4]" />
              <span>Visão Consolidada de Portfólio &amp; Evolução entre Releases</span>
            </h2>
            <button
              type="button"
              onClick={() => void loadPortfolio()}
              disabled={portfolioLoading}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 hover:border-[#31d6c4] cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${portfolioLoading ? 'animate-spin' : ''}`} />
              <span>Atualizar Portfólio</span>
            </button>
          </div>

          {!portfolio ? (
            <div className="p-8 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] text-center text-xs text-slate-500 font-mono">
              {portfolioLoading
                ? 'Carregando métricas do portfólio...'
                : 'Sem dados de portfólio carregados.'}
            </div>
          ) : (
            <>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                {[
                  {
                    label: 'Projetos / Softwares',
                    value: `${portfolio.totalProjects} / ${portfolio.totalSoftwares}`,
                  },
                  {
                    label: 'Runs / Manifestos Verificados',
                    value: `${portfolio.totalRuns} / ${portfolio.verifiedRunsCount}`,
                  },
                  {
                    label: 'Taxa Veracidade Assinada',
                    value:
                      portfolio.verifiedRunsRatePercent !== null
                        ? `${portfolio.verifiedRunsRatePercent.toFixed(1)}%`
                        : 'NOT_MEASURED',
                  },
                  {
                    label: 'Cobertura Média de Escopo',
                    value:
                      portfolio.avgScopeCoveragePercent !== null
                        ? `${portfolio.avgScopeCoveragePercent.toFixed(1)}%`
                        : 'NOT_MEASURED',
                  },
                  {
                    label: 'Dívida Técnica Acumulada',
                    value: `${portfolio.totalTechnicalDebtMinutes} min`,
                  },
                ].map((kpi) => (
                  <div
                    key={kpi.label}
                    className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] space-y-1"
                  >
                    <div className="text-[11px] text-slate-500">{kpi.label}</div>
                    <div className="text-lg font-mono font-bold tabular-nums text-slate-900 dark:text-slate-100">
                      {kpi.value}
                    </div>
                  </div>
                ))}
              </div>

              {/* Explicit Uncovered Scope Transparency */}
              <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-500/5 text-xs space-y-1.5">
                <div className="font-bold text-amber-500 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  <span>Transparência de Dimensões Não Cobertas no Portfólio</span>
                </div>
                <p className="text-slate-600 dark:text-slate-300">
                  {portfolio.uncoveredDimensionsSummary.length > 0
                    ? `Dimensões sem medição completa neste portfólio: ${portfolio.uncoveredDimensionsSummary
                        .map((u) => `${u.category} (${u.unmeasuredRunsCount} runs)`)
                        .join(', ')}. O WinHood não converte ausência de dados em aprovação.`
                    : 'Todas as dimensões elegíveis das execuções concluídas possuem medição formal registrada.'}
                </p>
              </div>

              {/* Release Progression Table */}
              <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-3">
                <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                  Linha do Tempo por Release (Nota, Escopo &amp; Deltas)
                </h3>
                {portfolio.releaseProgression.length === 0 ? (
                  <p className="text-xs text-slate-500">
                    Nenhuma avaliação registrada no portfólio ainda.
                  </p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                      <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                          <th className="py-2 pr-3">Software / Versão</th>
                          <th className="py-2 px-3">Nota (Delta)</th>
                          <th className="py-2 px-3">Achados (Delta)</th>
                          <th className="py-2 px-3">Escopo / Confiança</th>
                          <th className="py-2 pl-3">Gate / Veracidade</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                        {portfolio.releaseProgression.map((r) => (
                          <tr key={`${r.runId}-${r.softwareId}`}>
                            <td className="py-2 pr-3 font-sans">
                              <div className="font-semibold text-slate-900 dark:text-slate-100">
                                {r.softwareName} v{r.softwareVersion}
                              </div>
                              <div className="font-mono text-[10px] text-slate-400">
                                {r.runId} · {new Date(r.completedAt).toLocaleDateString('pt-BR')}
                              </div>
                            </td>
                            <td className="py-2 px-3 font-bold">
                              {r.overallScore !== null ? `${r.overallScore.toFixed(2)}` : 'N/A'}
                              {r.deltaScoreFromPrevious !== null && (
                                <span
                                  className={`ml-1.5 inline-flex items-center gap-0.5 text-[10px] ${
                                    r.deltaScoreFromPrevious >= 0
                                      ? 'text-emerald-500'
                                      : 'text-rose-500'
                                  }`}
                                >
                                  {r.deltaScoreFromPrevious >= 0 ? (
                                    <TrendingUp className="w-3 h-3" />
                                  ) : (
                                    <TrendingDown className="w-3 h-3" />
                                  )}
                                  {r.deltaScoreFromPrevious >= 0
                                    ? `+${r.deltaScoreFromPrevious.toFixed(2)}`
                                    : r.deltaScoreFromPrevious.toFixed(2)}
                                </span>
                              )}
                            </td>
                            <td className="py-2 px-3">
                              {r.totalFindings} ({r.criticalOrBlockerFindings} crit)
                              {r.deltaFindingsFromPrevious !== null && (
                                <span
                                  className={`ml-1.5 text-[10px] ${
                                    r.deltaFindingsFromPrevious <= 0
                                      ? 'text-emerald-500'
                                      : 'text-rose-500'
                                  }`}
                                >
                                  {r.deltaFindingsFromPrevious > 0
                                    ? `+${r.deltaFindingsFromPrevious}`
                                    : r.deltaFindingsFromPrevious}
                                </span>
                              )}
                            </td>
                            <td className="py-2 px-3 text-slate-400">
                              {r.scopeCoveragePercent.toFixed(0)}% · {r.evidenceConfidence}
                            </td>
                            <td className="py-2 pl-3">
                              <span className="text-[#31d6c4] font-bold">{r.gateDecision}</span>
                              <span className="text-[10px] text-slate-400 block">
                                {r.evidenceVerified ? 'MANIFEST_VERIFIED' : 'UNVERIFIED'}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Finding Trends Table */}
              {portfolio.findingTrends.length > 0 && (
                <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-3">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                    Tendência de Achados &amp; Dívida Técnica por Execução
                  </h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                      <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                          <th className="py-2 pr-3">Execução</th>
                          <th className="py-2 px-3 text-rose-500">Blocker/Critical</th>
                          <th className="py-2 px-3 text-orange-400">High</th>
                          <th className="py-2 px-3 text-amber-400">Medium/Low</th>
                          <th className="py-2 px-3">Total</th>
                          <th className="py-2 pl-3">Dívida</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                        {portfolio.findingTrends.map((t) => (
                          <tr key={t.runId}>
                            <td className="py-2 pr-3 text-[#31d6c4] font-sans">{t.label}</td>
                            <td className="py-2 px-3 font-bold text-rose-500">
                              {t.blockerOrCritical}
                            </td>
                            <td className="py-2 px-3 text-orange-400">{t.high}</td>
                            <td className="py-2 px-3 text-amber-400">{t.mediumOrLow}</td>
                            <td className="py-2 px-3 font-bold">{t.total}</td>
                            <td className="py-2 pl-3 text-slate-400">
                              {t.technicalDebtMinutes} min
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* SUB-TAB 3: COMPLIANCE TRACEABILITY MATRIX */}
      {subTab === 'compliance' && (
        <div className="space-y-6">
          <div className="p-4 rounded-xl border border-amber-500/40 bg-amber-500/10 text-xs flex items-start gap-3">
            <ShieldAlert className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold text-amber-600 dark:text-amber-300">
                AVISO OBRIGATÓRIO: RASTREABILIDADE TÉCNICA (NÃO EQUIVALE A CERTIFICAÇÃO FORMAL)
              </div>
              <p className="text-slate-700 dark:text-slate-200">
                {compliance?.disclaimer ||
                  'Este mapeamento correlaciona achados técnicos com controles de referência OWASP Top 10, CWE Top 25, PCI DSS v4.0 e ISO/IEC 27001:2022 apenas para rastreabilidade de engenharia. Não constitui nem substitui auditoria ou certificação formal.'}
              </p>
            </div>
          </div>

          {!latestRun ? (
            <div className="p-8 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] text-center text-xs text-slate-500">
              Execute um benchmark para mapear seus achados contra os controles OWASP, CWE, PCI DSS e ISO 27001.
            </div>
          ) : complianceLoading || !compliance ? (
            <div className="p-8 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] text-center text-xs font-mono text-slate-500">
              Calculando matriz de rastreabilidade...
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-2">
                {(Object.keys(FRAMEWORK_LABELS) as ComplianceFrameworkKey[]).map((fwKey) => {
                  const controls = compliance.byFramework[fwKey] || [];
                  const withFindings = controls.filter(
                    (c) => c.status === 'FINDINGS_DETECTED'
                  ).length;
                  return (
                    <button
                      key={fwKey}
                      type="button"
                      onClick={() => setSelectedFramework(fwKey)}
                      className={`px-3.5 py-2 rounded-lg text-xs font-semibold border transition-colors cursor-pointer ${
                        selectedFramework === fwKey
                          ? 'bg-[#31d6c4]/15 border-[#31d6c4] text-[#0e9f8e] dark:text-[#31d6c4]'
                          : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] text-slate-600 dark:text-slate-300'
                      }`}
                    >
                      {FRAMEWORK_LABELS[fwKey]} ({withFindings} com achados)
                    </button>
                  );
                })}
              </div>

              <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                      {FRAMEWORK_LABELS[selectedFramework]}
                    </h3>
                    <p className="text-[11px] text-slate-500 mt-0.5">
                      Total de achados ativos correlacionados na execução: {compliance.totalFindingsMapped}
                    </p>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 font-mono text-[11px] text-slate-500">
                        <th className="py-2 pr-3">Controle</th>
                        <th className="py-2 px-3">Descrição</th>
                        <th className="py-2 px-3">Estado Observado</th>
                        <th className="py-2 px-3">Achados (Crit/Block)</th>
                        <th className="py-2 pl-3">CWEs Associados</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                      {activeFrameworkControls.map((c) => (
                        <tr key={c.controlId}>
                          <td className="py-2.5 pr-3 font-mono font-bold text-[#31d6c4] whitespace-nowrap">
                            {c.controlId}
                          </td>
                          <td className="py-2.5 px-3 font-medium text-slate-800 dark:text-slate-200">
                            {c.controlTitle}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[11px] whitespace-nowrap">
                            <span
                              className={
                                c.status === 'FINDINGS_DETECTED'
                                  ? 'text-rose-500 font-bold'
                                  : 'text-emerald-500'
                              }
                            >
                              {c.status}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 font-mono tabular-nums font-bold">
                            {c.findingsCount} ({c.criticalOrBlockerCount})
                          </td>
                          <td className="py-2.5 pl-3 font-mono text-[10px] text-[#31d6c4]">
                            {c.matchedCwes.length > 0 ? c.matchedCwes.join(', ') : '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUB-TAB 4: PUBLIC RULE CATALOG, SECRETS CATALOG & OPENAPI */}
      {subTab === 'catalog' && (
        <div className="space-y-6">
          {/* Engine Version & OpenAPI Banner */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] space-y-1">
              <div className="text-[11px] text-slate-500">Motor Nativo de Regras</div>
              <div className="font-mono text-sm font-bold text-[#31d6c4]">
                v{rulesCatalog?.engineVersion || '4.3.0'} · {rulesCatalog?.totalRules ?? 0} regras
              </div>
              <div className="font-mono text-[10px] text-slate-400 truncate">
                SHA-256: {rulesCatalog?.catalogSha256 || 'carregando...'}
              </div>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] space-y-1">
              <div className="text-[11px] text-slate-500">Catálogo Público de Segredos</div>
              <div className="font-mono text-sm font-bold text-slate-900 dark:text-slate-100">
                v{secretsCatalog?.version || '2026.11.0'} ·{' '}
                {secretsCatalog?.patternsCount ?? secretsCatalog?.patterns.length ?? 0} padrões
              </div>
              <div className="font-mono text-[10px] text-slate-400 truncate">
                SHA-256: {secretsCatalog?.checksumSha256 || 'carregando...'}
              </div>
            </div>

            <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] flex items-center justify-between gap-3">
              <div className="space-y-1 min-w-0">
                <div className="text-[11px] text-slate-500">Especificação REST OpenAPI 3.0.3</div>
                <div className="font-mono text-sm font-bold text-slate-900 dark:text-slate-100">
                  {openApiSummary
                    ? `${openApiSummary.pathCount} endpoints (v${openApiSummary.version})`
                    : 'OpenAPI 3.0.3'}
                </div>
              </div>
              <a
                href="/api/openapi.json"
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] shrink-0"
              >
                <Download className="w-3.5 h-3.5" />
                <span>JSON</span>
              </a>
            </div>
          </div>

          {/* Native Pluggable Analyzers */}
          {rulesCatalog && rulesCatalog.plugins.length > 0 && (
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-3">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <FileCode2 className="w-4 h-4 text-[#31d6c4]" />
                <span>Plugins Nativos Acoplados ao Pipeline (AnalyzerPlugin)</span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {rulesCatalog.plugins.map((pl) => (
                  <div
                    key={pl.id}
                    className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] text-xs space-y-1"
                  >
                    <div className="flex items-center justify-between font-bold">
                      <span>{pl.name}</span>
                      <span className="font-mono text-[#31d6c4]">v{pl.version}</span>
                    </div>
                    <div className="font-mono text-[10px] text-slate-400">
                      Linguagens: {pl.supportedLanguages.join(', ')}
                    </div>
                    <div className="font-mono text-[10px] text-slate-500">
                      Capacidades: {pl.capabilities.join(' · ')}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Searchable Rule Catalog with Positive/Negative Examples */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-[#31d6c4]" />
                <span>Catálogo Público de Regras ({filteredRules.length})</span>
              </h3>
              <div className="relative w-full sm:w-72">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  placeholder="Filtrar por ID, CWE, OWASP ou linguagem..."
                  value={catalogSearch}
                  onChange={(e) => setCatalogSearch(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] pl-8 pr-3 py-1.5 text-xs"
                />
              </div>
            </div>

            <div className="space-y-2 max-h-[460px] df-hover-scroll">
              {filteredRules.map((rule) => {
                const expanded = expandedRuleId === rule.ruleId;
                return (
                  <div
                    key={rule.ruleId}
                    className="rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#080b10]"
                  >
                    <button
                      type="button"
                      onClick={() => setExpandedRuleId(expanded ? null : rule.ruleId)}
                      className="w-full px-3.5 py-2.5 flex flex-wrap items-center justify-between gap-2 text-left text-xs cursor-pointer"
                    >
                      <div className="flex flex-wrap items-center gap-2 min-w-0">
                        <span className="font-mono font-bold text-[#31d6c4]">{rule.ruleId}</span>
                        <span className="px-1.5 py-0.5 rounded font-mono text-[10px] bg-slate-200 dark:bg-slate-800">
                          {rule.severity}
                        </span>
                        <span className="font-semibold text-slate-900 dark:text-slate-100 truncate">
                          {rule.title}
                        </span>
                      </div>
                      <div className="font-mono text-[10px] text-slate-400 flex items-center gap-2">
                        {rule.cwe && <span>{rule.cwe}</span>}
                        {rule.cvssBase !== undefined && <span>CVSS {rule.cvssBase.toFixed(1)}</span>}
                        <span>v{rule.version}</span>
                      </div>
                    </button>

                    {expanded && (
                      <div className="px-3.5 pb-3.5 pt-2 border-t border-slate-200 dark:border-slate-800 text-xs space-y-2">
                        <div className="font-mono text-[11px] text-slate-400 flex flex-wrap gap-3">
                          <span>Linguagens: {rule.languages.join(', ')}</span>
                          {rule.owaspTop10 && <span>OWASP: {rule.owaspTop10}</span>}
                          {rule.cweTop25Rank && <span>CWE Top 25: #{rule.cweTop25Rank}</span>}
                        </div>
                        <p className="text-slate-600 dark:text-slate-300">{rule.remediation}</p>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {rule.positiveExamples && rule.positiveExamples.length > 0 && (
                            <div>
                              <div className="text-[10px] font-mono text-rose-400 mb-1 flex items-center gap-1">
                                <Code2 className="w-3 h-3" /> Exemplo Vulnerável (Trigger Positivo)
                              </div>
                              <pre className="p-2 rounded bg-slate-950 text-rose-200 font-mono text-[10px] overflow-x-auto">
                                {rule.positiveExamples.join('\n')}
                              </pre>
                            </div>
                          )}
                          {rule.negativeExamples && rule.negativeExamples.length > 0 && (
                            <div>
                              <div className="text-[10px] font-mono text-emerald-400 mb-1 flex items-center gap-1">
                                <CheckCircle2 className="w-3 h-3" /> Exemplo Seguro (Negativo / Compliant)
                              </div>
                              <pre className="p-2 rounded bg-slate-950 text-emerald-200 font-mono text-[10px] overflow-x-auto">
                                {rule.negativeExamples.join('\n')}
                              </pre>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Documented Secrets False-Positive Exclusions */}
          {secretsCatalog && (
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-3">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-[#31d6c4]" />
                <span>Política de Detecção de Segredos &amp; Exclusões de Falso Positivo</span>
              </h3>
              <ul className="list-disc list-inside text-xs text-slate-600 dark:text-slate-300 space-y-1">
                {secretsCatalog.documentedExclusions.map((ex, i) => (
                  <li key={i}>{ex}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
