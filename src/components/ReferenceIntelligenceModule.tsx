import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  Download,
  FileCode2,
  GitCompare,
  KeyRound,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  XCircle,
} from 'lucide-react';
import type {
  AuthorizedPerfTarget,
  BenchmarkMatchDecision,
  BenchmarkRun,
  GoldenValidationSuiteReport,
  ReferenceSnapshotRecord,
  ScaVulnerabilityCorrelation,
  Software,
} from '../types/benchmark';

interface KeyStatusRecord {
  keyId: string;
  purpose: 'EVIDENCE_HMAC' | 'EVIDENCE_ED25519' | 'TOKEN_VAULT_AES256' | 'ADMIN_RBAC';
  createdAt: string;
  rotatedAt?: string | null;
  status: 'ACTIVE' | 'RETIRED_VERIFY_ONLY';
  fingerprintSha256: string;
}

interface KeyStatusPayload {
  keystorePath: string;
  keyOrigin: string;
  activeEvidenceKeyId: string;
  activeEd25519KeyId?: string;
  activeVaultKeyId: string;
  adminTokenConfigured: boolean;
  totalKeysTracked: number;
  keys: KeyStatusRecord[];
}

interface ReferenceIntelligenceModuleProps {
  latestRun: BenchmarkRun | null;
  softwares: Software[];
  onNotify: (msg: string, type?: 'success' | 'error') => void;
}

type SubTabId = 'references' | 'matcher' | 'golden' | 'sbom_sca' | 'execution_keys';

export const ReferenceIntelligenceModule: React.FC<ReferenceIntelligenceModuleProps> = ({
  latestRun,
  softwares,
  onNotify,
}) => {
  const [subTab, setSubTab] = useState<SubTabId>('references');

  // 1. Reference Registry & Sync
  const [snapshots, setSnapshots] = useState<ReferenceSnapshotRecord[]>([]);
  const [refCounters, setRefCounters] = useState<{
    totalSources: number;
    freshCount: number;
    cachedCount: number;
    staleCount: number;
  }>({ totalSources: 0, freshCount: 0, cachedCount: 0, staleCount: 0 });
  const [loadingRefs, setLoadingRefs] = useState(false);
  const [syncingRefs, setSyncingRefs] = useState(false);
  const [sonarSyncUrl, setSonarSyncUrl] = useState('http://localhost:9000');

  // 2. Comparability Matcher (11 Criteria)
  const [selectedMatchSwIds, setSelectedMatchSwIds] = useState<string[]>([]);
  const [matchMode, setMatchMode] = useState<BenchmarkMatchDecision['mode']>('AB_SOFTWARE');
  const [matchDecision, setMatchDecision] = useState<BenchmarkMatchDecision | null>(null);
  const [matchLoading, setMatchLoading] = useState(false);

  // 3. Golden Dataset (20 paired TP/TN cases)
  const [goldenReport, setGoldenReport] = useState<GoldenValidationSuiteReport | null>(null);
  const [goldenLoading, setGoldenLoading] = useState(false);

  // 4. SBOM & SCA
  const [sbomFormat, setSbomFormat] = useState<'cyclonedx' | 'spdx'>('cyclonedx');
  const [sbomSwId, setSbomSwId] = useState<string>('');
  const [sbomData, setSbomData] = useState<{
    runId: string;
    softwareId: string;
    format: 'cyclonedx' | 'spdx';
    document: Record<string, unknown>;
    documentSha256: string;
    componentsCount: number;
    directCount: number;
    transitiveCount: number;
    scaCorrelations: ScaVulnerabilityCorrelation[];
  } | null>(null);
  const [sbomLoading, setSbomLoading] = useState(false);
  const [sbomError, setSbomError] = useState<string | null>(null);

  // 5. Execution & Key Management
  const [execSwId, setExecSwId] = useState<string>('');
  const [testExecResult, setTestExecResult] = useState<any>(null);
  const [testExecLoading, setTestExecLoading] = useState(false);
  const [perfUrl, setPerfUrl] = useState('http://127.0.0.1:3000/api/health');
  const [perfRequests, setPerfRequests] = useState(20);
  const [perfConcurrency, setPerfConcurrency] = useState(4);
  const [perfResult, setPerfResult] = useState<any>(null);
  const [perfLoading, setPerfLoading] = useState(false);
  const [targets, setTargets] = useState<AuthorizedPerfTarget[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<string>('');
  const [newTargetLabel, setNewTargetLabel] = useState('');
  const [newTargetOrigin, setNewTargetOrigin] = useState('http://127.0.0.1:3000');
  const [newTargetPurpose, setNewTargetPurpose] = useState('Profiling HTTP controlado');
  const [allowLocalhostInTest, setAllowLocalhostInTest] = useState(true);
  const [savingTarget, setSavingTarget] = useState(false);
  const [keyStatus, setKeyStatus] = useState<KeyStatusPayload | null>(null);
  const [rotatingKey, setRotatingKey] = useState<string | null>(null);

  useEffect(() => {
    if (softwares.length > 0) {
      if (selectedMatchSwIds.length === 0) {
        setSelectedMatchSwIds(softwares.slice(0, 2).map((s) => s.id));
      }
      if (!sbomSwId) {
        setSbomSwId(softwares[0].id);
      }
      if (!execSwId) {
        setExecSwId(softwares[0].id);
      }
    }
  }, [softwares, selectedMatchSwIds.length, sbomSwId, execSwId]);

  const fetchReferences = useCallback(async () => {
    setLoadingRefs(true);
    try {
      const res = await fetch('/api/intelligence/references');
      if (res.ok) {
        const data = await res.json();
        setSnapshots(data.snapshots || []);
        setRefCounters({
          totalSources: data.totalSources || 0,
          freshCount: data.freshCount || 0,
          cachedCount: data.cachedCount || 0,
          staleCount: data.staleCount || 0,
        });
      }
    } catch {
      onNotify('Falha ao consultar fontes de referência.', 'error');
    } finally {
      setLoadingRefs(false);
    }
  }, [onNotify]);

  const fetchGoldenLatest = useCallback(async () => {
    setGoldenLoading(true);
    try {
      const res = await fetch('/api/validation/latest');
      if (res.ok) {
        const data = await res.json();
        setGoldenReport(data.report || null);
      }
    } catch {
      onNotify('Falha ao carregar relatório Golden Dataset.', 'error');
    } finally {
      setGoldenLoading(false);
    }
  }, [onNotify]);

  const fetchKeyStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/security/keys/status');
      if (res.ok) {
        const data = await res.json();
        setKeyStatus(data.keys || null);
      }
    } catch {
      // Ignore transient error
    }
  }, []);

  const fetchPerfTargets = useCallback(async () => {
    try {
      const res = await fetch('/api/execution/targets');
      if (res.ok) {
        const data = await res.json();
        const list = (data.targets || []) as AuthorizedPerfTarget[];
        setTargets(list);
        if (list.length > 0 && !selectedTargetId) {
          setSelectedTargetId(list[0].id);
          setPerfUrl(`${list[0].origin}/api/health`);
        }
      }
    } catch {
      // Ignore transient error
    }
  }, [selectedTargetId]);

  const fetchSbom = useCallback(async () => {
    if (!latestRun && softwares.length === 0) {
      setSbomData(null);
      return;
    }
    const targetRunId = latestRun?.id || 'latest';
    const targetSwId = sbomSwId || latestRun?.softwareIds?.[0] || softwares[0]?.id;
    if (!targetSwId) return;
    setSbomLoading(true);
    setSbomError(null);
    try {
      const res = await fetch(
        `/api/runs/${encodeURIComponent(targetRunId)}/sbom?format=${sbomFormat}&softwareId=${encodeURIComponent(targetSwId)}`
      );
      const data = await res.json();
      if (res.ok) {
        setSbomData(data);
      } else {
        setSbomData(null);
        setSbomError(data.error || 'SBOM não disponível sem execução de benchmark concluída.');
      }
    } catch {
      setSbomData(null);
      setSbomError('Erro de comunicação ao consultar SBOM e correlações SCA.');
    } finally {
      setSbomLoading(false);
    }
  }, [latestRun, softwares, sbomSwId, sbomFormat]);

  useEffect(() => {
    void fetchReferences();
    void fetchKeyStatus();
    void fetchPerfTargets();
  }, [fetchReferences, fetchKeyStatus, fetchPerfTargets]);

  useEffect(() => {
    if (subTab === 'golden' && !goldenReport) {
      void fetchGoldenLatest();
    } else if (subTab === 'sbom_sca') {
      void fetchSbom();
    } else if (subTab === 'execution_keys') {
      void fetchKeyStatus();
      void fetchPerfTargets();
    }
  }, [subTab, goldenReport, fetchGoldenLatest, fetchSbom, fetchKeyStatus, fetchPerfTargets]);

  const handleSyncReferences = async () => {
    setSyncingRefs(true);
    try {
      const res = await fetch('/api/intelligence/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sonarServerUrl: sonarSyncUrl }),
      });
      const data = await res.json();
      if (res.ok) {
        setSnapshots(data.snapshots || []);
        setRefCounters({
          totalSources: (data.snapshots || []).length,
          freshCount: (data.snapshots || []).filter((s: ReferenceSnapshotRecord) => s.freshnessStatus === 'FRESH').length,
          cachedCount: (data.snapshots || []).filter(
            (s: ReferenceSnapshotRecord) =>
              s.freshnessStatus === 'CACHED_VALID' || s.freshnessStatus === 'UNAVAILABLE_USING_CACHED'
          ).length,
          staleCount: (data.snapshots || []).filter((s: ReferenceSnapshotRecord) => s.freshnessStatus === 'STALE').length,
        });
        onNotify(
          `Sincronização concluída: ${data.liveFetchedSources?.length || 0} fonte(s) ao vivo, ${data.cachedFallbackSources?.length || 0} preservadas em cache válido.`,
          'success'
        );
      } else {
        onNotify(data.error || 'Falha ao sincronizar referências.', 'error');
      }
    } catch {
      onNotify('Erro ao sincronizar fontes externas.', 'error');
    } finally {
      setSyncingRefs(false);
    }
  };

  const handleRunMatcher = async () => {
    setMatchLoading(true);
    try {
      const res = await fetch('/api/intelligence/match', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          softwareIds: selectedMatchSwIds,
          mode: matchMode,
        }),
      });
      const data = await res.json();
      if (res.ok && data.decision) {
        setMatchDecision(data.decision);
        onNotify(
          data.decision.canDeclareOfficialWinner
            ? `Comparabilidade validada (${data.decision.compatibilityScorePercent}%).`
            : `Comparabilidade bloqueada (${data.decision.blockingReasons.length} bloqueio(s)).`,
          data.decision.canDeclareOfficialWinner ? 'success' : 'error'
        );
      } else {
        onNotify(data.error || 'Falha ao avaliar comparabilidade.', 'error');
      }
    } catch {
      onNotify('Erro de rede ao executar BenchmarkMatcher.', 'error');
    } finally {
      setMatchLoading(false);
    }
  };

  const handleRunGolden = async () => {
    setGoldenLoading(true);
    try {
      const res = await fetch('/api/validation/run-golden', { method: 'POST' });
      const data = await res.json();
      if (res.ok && data.report) {
        setGoldenReport(data.report);
        onNotify(
          `Suíte Golden executada: Precision ${(data.report.precision * 100).toFixed(1)}% · Recall ${(data.report.recall * 100).toFixed(1)}% · F1 ${(data.report.f1Score * 100).toFixed(1)}%`,
          'success'
        );
      } else {
        onNotify(data.error || 'Falha ao executar Suíte Golden.', 'error');
      }
    } catch {
      onNotify('Erro ao executar Suíte Golden.', 'error');
    } finally {
      setGoldenLoading(false);
    }
  };

  const handleDownloadSbom = () => {
    if (!sbomData?.document) return;
    const blob = new Blob([JSON.stringify(sbomData.document, null, 2)], {
      type: 'application/json;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `winhood-${sbomData.softwareId}-${sbomData.format}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setTimeout(() => URL.revokeObjectURL(url), 4000);
    onNotify(`SBOM (${sbomData.format.toUpperCase()}) exportado com SHA-256 verificado.`, 'success');
  };

  const handleRunIsolatedTests = async () => {
    if (!execSwId) {
      onNotify('Selecione ou cadastre um software primeiro.', 'error');
      return;
    }
    setTestExecLoading(true);
    try {
      const res = await fetch('/api/execution/run-tests', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ softwareId: execSwId }),
      });
      const data = await res.json();
      if (res.ok) {
        setTestExecResult(data);
        onNotify(
          `Testes executados (${data.result?.runnerUsed || 'NONE'}): ${data.result?.testsPassed ?? 0}/${data.result?.testsTotal ?? 0}.`,
          'success'
        );
      } else {
        onNotify(data.error || 'Falha na execução isolada de testes.', 'error');
      }
    } catch {
      onNotify('Erro ao executar suíte isolada de testes.', 'error');
    } finally {
      setTestExecLoading(false);
    }
  };

  const handleRegisterPerfTarget = async () => {
    if (!newTargetOrigin.trim()) {
      onNotify('Informe a origem HTTP/HTTPS do alvo autorizado.', 'error');
      return;
    }
    setSavingTarget(true);
    try {
      const res = await fetch('/api/execution/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          label: newTargetLabel.trim() || newTargetOrigin.trim(),
          origin: newTargetOrigin.trim(),
          purpose: newTargetPurpose.trim() || 'Medição controlada de latência HTTP',
          allowLocalhostInTest,
        }),
      });
      const data = await res.json();
      if (res.ok && data.target) {
        setNewTargetLabel('');
        await fetchPerfTargets();
        setSelectedTargetId(data.target.id);
        setPerfUrl(`${data.target.origin}/api/health`);
        onNotify(`Alvo autorizado "${data.target.label}" homologado com proteção SSRF.`, 'success');
      } else {
        onNotify(data.message || data.error || 'Alvo bloqueado por política SSRF.', 'error');
      }
    } catch {
      onNotify('Erro ao cadastrar alvo autorizado.', 'error');
    } finally {
      setSavingTarget(false);
    }
  };

  const handleDeletePerfTarget = async (id: string) => {
    try {
      const res = await fetch(`/api/execution/targets/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        if (selectedTargetId === id) setSelectedTargetId('');
        await fetchPerfTargets();
        onNotify('Alvo autorizado removido.', 'success');
      } else {
        const data = await res.json();
        onNotify(data.message || data.error || 'Erro ao remover alvo.', 'error');
      }
    } catch {
      onNotify('Erro de rede ao remover alvo.', 'error');
    }
  };

  const handleRunHttpPerf = async () => {
    setPerfLoading(true);
    try {
      const res = await fetch('/api/execution/run-perf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          softwareId: execSwId || undefined,
          targetId: selectedTargetId || undefined,
          targetUrl: perfUrl,
          requestsCount: perfRequests,
          concurrency: perfConcurrency,
          allowExplicitLoopback: allowLocalhostInTest,
        }),
      });
      const data = await res.json();
      if (res.ok && data.result) {
        setPerfResult(data.result);
        onNotify(
          data.result.status === 'MEASURED'
            ? `Medição HTTP real concluída: P95 ${data.result.p95LatencyMs}ms · ${data.result.throughputRps} req/s.`
            : `Medição HTTP retornou ${data.result.status} (${data.result.errorMessage || 'verifique alvo autorizado'}).`,
          data.result.status === 'MEASURED' ? 'success' : 'error'
        );
      } else {
        onNotify(data.message || data.error || 'Alvo recusado pelo SSRF Guard ou sem autorização.', 'error');
      }
    } catch {
      onNotify('Erro ao executar medição HTTP.', 'error');
    } finally {
      setPerfLoading(false);
    }
  };

  const handleRotateKey = async (
    purpose: 'EVIDENCE_HMAC' | 'EVIDENCE_ED25519' | 'TOKEN_VAULT_AES256'
  ) => {
    setRotatingKey(purpose);
    try {
      const res = await fetch('/api/security/keys/rotate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ purpose }),
      });
      const data = await res.json();
      if (res.ok && data.keys) {
        setKeyStatus(data.keys);
        onNotify(`Chave ${purpose} rotacionada para ${data.newKeyId}. Chaves anteriores preservadas para auditoria.`, 'success');
      } else {
        onNotify(data.message || data.error || 'Falha ao rotacionar chave.', 'error');
      }
    } catch {
      onNotify('Erro ao rotacionar chave criptográfica.', 'error');
    } finally {
      setRotatingKey(null);
    }
  };

  const freshnessBadge = (status: ReferenceSnapshotRecord['freshnessStatus']) => {
    if (status === 'FRESH') {
      return 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30';
    }
    if (status === 'CACHED_VALID' || status === 'UNAVAILABLE_USING_CACHED') {
      return 'bg-amber-500/15 text-amber-500 border-amber-500/30';
    }
    return 'bg-rose-500/15 text-rose-500 border-rose-500/30';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2.5">
            <Database className="w-6 h-6 text-[#31d6c4] shrink-0" />
            <span>Inteligência de Referência, Golden Dataset, SBOM &amp; Chaves</span>
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1 max-w-4xl">
            Fontes oficiais versionadas com fallback offline seguro, comparabilidade em 11 critérios, calibração TP/TN OWASP, CycloneDX/SPDX + CVE/EPSS/KEV e rotação criptográfica.
          </p>
        </div>

        {/* Sub-Tabs */}
        <div
          role="tablist"
          aria-label="Submódulos de Inteligência e Validação"
          className="flex flex-wrap items-center gap-1.5 p-1 rounded-lg bg-slate-200/70 dark:bg-[#0f141c] border border-slate-300/60 dark:border-slate-800 w-fit max-w-full"
        >
          {[
            { id: 'references', label: 'Fontes de Referência (10)', icon: Database },
            { id: 'matcher', label: 'Comparabilidade (11 Critérios)', icon: GitCompare },
            { id: 'golden', label: 'Golden Dataset (OWASP)', icon: Sparkles },
            { id: 'sbom_sca', label: 'SBOM & SCA (CVE/EPSS/KEV)', icon: FileCode2 },
            { id: 'execution_keys', label: 'Execução Controlada & Chaves', icon: KeyRound },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = subTab === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setSubTab(tab.id as SubTabId)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-colors whitespace-nowrap cursor-pointer ${
                  active
                    ? 'bg-[#31d6c4] text-slate-950'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
                }`}
              >
                <Icon className="w-3.5 h-3.5 shrink-0" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* TAB 1: 10 MANDATORY REFERENCE SOURCES */}
      {subTab === 'references' && (
        <div className="space-y-5">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-4">
              <div className="text-xs text-slate-500">Fontes Obrigatórias</div>
              <div className="text-2xl font-bold font-mono tabular-nums text-slate-900 dark:text-slate-100 mt-1">
                {refCounters.totalSources} / 10
              </div>
            </div>
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-4">
              <div className="text-xs text-slate-500">Atualizadas (FRESH)</div>
              <div className="text-2xl font-bold font-mono tabular-nums text-emerald-500 mt-1">
                {refCounters.freshCount}
              </div>
            </div>
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-4">
              <div className="text-xs text-slate-500">Cache Válido / Fallback</div>
              <div className="text-2xl font-bold font-mono tabular-nums text-amber-500 mt-1">
                {refCounters.cachedCount}
              </div>
            </div>
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-4">
              <div className="text-xs text-slate-500">Desatualizadas (STALE)</div>
              <div className="text-2xl font-bold font-mono tabular-nums text-rose-500 mt-1">
                {refCounters.staleCount}
              </div>
            </div>
          </div>

          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Registro Permanente de Inteligência &amp; Snapshots Versionados
                </h2>
                <p className="text-xs text-slate-500">
                  Cada referência preserva versão, origem, licença, hash SHA-256 e estado de frescor (fallback automático para o último snapshot válido quando offline).
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <input
                  type="url"
                  aria-label="URL SonarQube Server para sincronização"
                  value={sonarSyncUrl}
                  onChange={(e) => setSonarSyncUrl(e.target.value)}
                  placeholder="http://localhost:9000"
                  className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] text-xs font-mono text-slate-900 dark:text-slate-100 w-52"
                />
                <button
                  type="button"
                  onClick={handleSyncReferences}
                  disabled={syncingRefs || loadingRefs}
                  className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-60"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${syncingRefs ? 'animate-spin' : ''}`} />
                  <span>{syncingRefs ? 'Sincronizando...' : 'Sincronizar Fontes'}</span>
                </button>
              </div>
            </div>

            <div className="overflow-x-auto df-hover-scroll">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                    <th className="py-2.5 pr-3">Fonte</th>
                    <th className="py-2.5 px-3">Versão</th>
                    <th className="py-2.5 px-3">Licença</th>
                    <th className="py-2.5 px-3">Estado</th>
                    <th className="py-2.5 px-3">SHA-256</th>
                    <th className="py-2.5 pl-3">Data / Origem</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
                  {snapshots.map((snap) => (
                    <tr key={snap.sourceKey} className="hover:bg-slate-50 dark:hover:bg-slate-800/30">
                      <td className="py-3 pr-3">
                        <div className="font-bold text-slate-900 dark:text-slate-100">
                          {snap.sourceName}
                        </div>
                        <div className="text-[11px] font-mono text-slate-500">{snap.sourceKey}</div>
                      </td>
                      <td className="py-3 px-3 font-mono text-slate-700 dark:text-slate-300">
                        {snap.version}
                      </td>
                      <td className="py-3 px-3 text-slate-600 dark:text-slate-400">{snap.license}</td>
                      <td className="py-3 px-3">
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-mono font-bold ${freshnessBadge(
                            snap.freshnessStatus
                          )}`}
                        >
                          {snap.freshnessStatus}
                        </span>
                        {snap.isOfflineFallback && (
                          <div className="text-[10px] text-amber-500 mt-0.5">
                            Offline Fallback Ativo
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-3 font-mono text-[11px] text-[#31d6c4]">
                        {snap.sha256.slice(0, 16)}...
                      </td>
                      <td className="py-3 pl-3 text-[11px]">
                        <div className="font-mono text-slate-500">
                          {new Date(snap.fetchedAt).toLocaleString('pt-BR')}
                        </div>
                        <div className="text-slate-400 truncate max-w-[240px]" title={snap.originUrl}>
                          {snap.originUrl}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: BENCHMARK MATCHER (11 CRITERIA) */}
      {subTab === 'matcher' && (
        <div className="space-y-5">
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  BenchmarkMatcher — Verificação de Comparabilidade em 11 Critérios
                </h2>
                <p className="text-xs text-slate-500">
                  Bloqueia declaração de vencedor oficial se houver divergência de linguagem, domínio, versão de motor, Quality Gate ou cobertura de testes.
                </p>
              </div>
              <button
                type="button"
                onClick={handleRunMatcher}
                disabled={matchLoading}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-60"
              >
                <GitCompare className="w-3.5 h-3.5" />
                <span>{matchLoading ? 'Validando 11 Critérios...' : 'Validar Comparabilidade'}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div>
                <label className="block font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                  Modo de Comparação
                </label>
                <select
                  aria-label="Modo de comparação"
                  value={matchMode}
                  onChange={(e) => setMatchMode(e.target.value as BenchmarkMatchDecision['mode'])}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 font-mono text-slate-900 dark:text-slate-100"
                >
                  <option value="INDIVIDUAL">INDIVIDUAL (Auditoria Solo)</option>
                  <option value="AB_SOFTWARE">AB_SOFTWARE (Software A vs Software B)</option>
                  <option value="VS_SONARQUBE">VS_SONARQUBE (WinHood vs SonarQube Nativo)</option>
                  <option value="VS_PUBLIC_REFERENCE">VS_PUBLIC_REFERENCE (Baseline Público)</option>
                  <option value="VS_INTERNAL_HISTORY">VS_INTERNAL_HISTORY (Regressão Histórica)</option>
                </select>
              </div>

              <div>
                <span className="block font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                  Softwares Participantes ({selectedMatchSwIds.length} selecionados)
                </span>
                {softwares.length === 0 ? (
                  <div className="p-2 rounded border border-slate-300 dark:border-slate-700 text-slate-500">
                    Nenhum software cadastrado no workspace.
                  </div>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {softwares.map((sw) => {
                      const checked = selectedMatchSwIds.includes(sw.id);
                      return (
                        <button
                          key={sw.id}
                          type="button"
                          onClick={() =>
                            setSelectedMatchSwIds((prev) =>
                              prev.includes(sw.id) ? prev.filter((id) => id !== sw.id) : [...prev, sw.id]
                            )
                          }
                          className={`px-2.5 py-1.5 rounded-lg border text-xs font-medium cursor-pointer ${
                            checked
                              ? 'bg-[#31d6c4]/15 border-[#31d6c4] text-[#0e9f8e] dark:text-[#31d6c4]'
                              : 'border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-400'
                          }`}
                        >
                          {sw.name} (v{sw.version})
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {matchDecision && (
              <div className="space-y-4 pt-3 border-t border-slate-200 dark:border-slate-800">
                <div
                  className={`p-4 rounded-lg border flex flex-wrap items-center justify-between gap-3 ${
                    matchDecision.canDeclareOfficialWinner
                      ? 'border-emerald-500/40 bg-emerald-500/10'
                      : 'border-rose-500/40 bg-rose-500/10'
                  }`}
                >
                  <div>
                    <div className="text-xs font-mono font-bold text-slate-900 dark:text-slate-100">
                      {matchDecision.canDeclareOfficialWinner
                        ? 'VENCEDOR OFICIAL HABILITADO'
                        : 'COMPARAÇÃO BLOQUEADA — VENCEDOR OFICIAL PROIBIDO'}
                    </div>
                    <div className="text-xs text-slate-600 dark:text-slate-300 mt-0.5">
                      {matchDecision.blockingReasons.length > 0
                        ? matchDecision.blockingReasons.join(' · ')
                        : 'Todos os critérios bloqueantes de paridade técnica foram satisfeitos.'}
                    </div>
                  </div>
                  <div className="text-right font-mono tabular-nums">
                    <div className="text-2xl font-bold text-[#31d6c4]">
                      {matchDecision.compatibilityScorePercent}%
                    </div>
                    <div className="text-[11px] text-slate-400">Compatibilidade</div>
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                        <th className="py-2 pr-3">Critério</th>
                        <th className="py-2 px-3">Severidade</th>
                        <th className="py-2 px-3">Resultado</th>
                        <th className="py-2 pl-3">Evidência &amp; Detalhe</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                      {matchDecision.checks.map((chk) => (
                        <tr key={chk.criterion}>
                          <td className="py-2.5 pr-3 font-mono font-bold text-slate-800 dark:text-slate-200">
                            {chk.criterion}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[11px] text-slate-500">
                            {chk.severity}
                          </td>
                          <td className="py-2.5 px-3">
                            {chk.passed ? (
                              <span className="inline-flex items-center gap-1 text-emerald-500 font-mono font-bold">
                                <CheckCircle2 className="w-3.5 h-3.5" /> PASS
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-rose-500 font-mono font-bold">
                                <XCircle className="w-3.5 h-3.5" /> FAIL
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 pl-3 text-slate-600 dark:text-slate-300">
                            {chk.detail}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: GOLDEN DATASET (20 PAIRED CASES) */}
      {subTab === 'golden' && (
        <div className="space-y-5">
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  Suíte Golden Dataset — Calibração Empírica (TP / FP / TN / FN)
                </h2>
                <p className="text-xs text-slate-500">
                  Executa o ParserRegistry + TaintAnalyzer reais contra 20 casos pareados (vulneráveis vs sanitizados) para medir Precision, Recall, F1, FPR e FNR sem mocks.
                </p>
              </div>
              <button
                type="button"
                onClick={handleRunGolden}
                disabled={goldenLoading}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-60"
              >
                <Play className="w-3.5 h-3.5" />
                <span>
                  {goldenLoading
                    ? 'Executando Corpus Golden...'
                    : 'Executar Suíte Golden (20 Casos TP/TN)'}
                </span>
              </button>
            </div>

            {goldenReport && (
              <>
                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 font-mono tabular-nums">
                  {[
                    { label: 'True Pos (TP)', val: goldenReport.truePositives, cls: 'text-emerald-500' },
                    { label: 'True Neg (TN)', val: goldenReport.trueNegatives, cls: 'text-emerald-500' },
                    { label: 'False Pos (FP)', val: goldenReport.falsePositives, cls: 'text-rose-500' },
                    { label: 'False Neg (FN)', val: goldenReport.falseNegatives, cls: 'text-rose-500' },
                    {
                      label: 'Precision',
                      val: goldenReport.precision !== null ? `${(goldenReport.precision * 100).toFixed(1)}%` : 'N/A',
                      cls: 'text-[#31d6c4]',
                    },
                    {
                      label: 'Recall',
                      val: goldenReport.recall !== null ? `${(goldenReport.recall * 100).toFixed(1)}%` : 'N/A',
                      cls: 'text-[#31d6c4]',
                    },
                    {
                      label: 'F1 Score',
                      val: goldenReport.f1Score !== null ? `${(goldenReport.f1Score * 100).toFixed(1)}%` : 'N/A',
                      cls: 'text-[#31d6c4]',
                    },
                    {
                      label: 'Duração Real',
                      val: `${goldenReport.totalDurationMs}ms`,
                      cls: 'text-slate-900 dark:text-slate-100',
                    },
                  ].map((item) => (
                    <div
                      key={item.label}
                      className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]"
                    >
                      <div className="text-[10px] font-sans text-slate-500">{item.label}</div>
                      <div className={`text-lg font-bold mt-1 ${item.cls}`}>{item.val}</div>
                    </div>
                  ))}
                </div>

                <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-500/10 text-xs text-amber-600 dark:text-amber-300 space-y-1">
                  <div className="font-bold">
                    Origem do Corpus: {goldenReport.datasetOriginLabel || 'WINHOOD_INTERNAL_CALIBRATION_CORPUS'}
                  </div>
                  <p className="text-[11px]">
                    {goldenReport.sampleWarning ||
                      'Corpus interno de calibração (N=20 casos pareados TP/TN): não substitui benchmark estatístico externo (NIST SARD / OWASP Benchmark oficial).'}
                  </p>
                  {goldenReport.datasetSha256 && (
                    <div className="font-mono text-[10px]">
                      SHA-256 Corpus: {goldenReport.datasetSha256}
                    </div>
                  )}
                </div>

                <div className="text-[11px] font-mono text-slate-500 flex flex-wrap gap-4">
                  <span>Dataset: {goldenReport.datasetVersion}</span>
                  <span>
                    FPR: {goldenReport.falsePositiveRate !== null ? `${(goldenReport.falsePositiveRate * 100).toFixed(2)}%` : 'N/A'}
                  </span>
                  <span>
                    FNR: {goldenReport.falseNegativeRate !== null ? `${(goldenReport.falseNegativeRate * 100).toFixed(2)}%` : 'N/A'}
                  </span>
                  <span>Delta RAM: {goldenReport.memoryDeltaMb} MB</span>
                  <span className="text-[#31d6c4]">SHA-256: {goldenReport.reportSha256.slice(0, 20)}...</span>
                </div>

                <div className="overflow-x-auto df-hover-scroll">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                        <th className="py-2 pr-3">Caso</th>
                        <th className="py-2 px-3">Linguagem</th>
                        <th className="py-2 px-3">CWE</th>
                        <th className="py-2 px-3">Esperado</th>
                        <th className="py-2 px-3">Detectado</th>
                        <th className="py-2 px-3">Classe</th>
                        <th className="py-2 pl-3 text-right">Duração</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                      {goldenReport.cases.map((c) => (
                        <tr key={c.caseId}>
                          <td className="py-2 pr-3">
                            <div className="font-mono font-bold text-slate-900 dark:text-slate-100">
                              {c.caseId}
                            </div>
                            <div className="text-[11px] text-slate-500">{c.title}</div>
                          </td>
                          <td className="py-2 px-3 font-mono">{c.language}</td>
                          <td className="py-2 px-3 font-mono text-[#31d6c4]">{c.cwe}</td>
                          <td className="py-2 px-3 font-mono">
                            {c.expectedVulnerable ? 'VULNERÁVEL' : 'SEGURO'}
                          </td>
                          <td className="py-2 px-3 font-mono">
                            {c.detectedVulnerable ? 'DETECTADO' : 'LIMPO'}
                          </td>
                          <td className="py-2 px-3">
                            <span
                              className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                                c.classification === 'TP' || c.classification === 'TN'
                                  ? 'bg-emerald-500/15 text-emerald-500'
                                  : 'bg-rose-500/15 text-rose-500'
                              }`}
                            >
                              {c.classification}
                            </span>
                          </td>
                          <td className="py-2 pl-3 text-right font-mono tabular-nums text-slate-500">
                            {c.durationMs}ms
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* TAB 4: SBOM & SCA */}
      {subTab === 'sbom_sca' && (
        <div className="space-y-5">
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  SBOM (CycloneDX 1.5 / SPDX 2.3) &amp; Correlação SCA (CVE / GHSA / EPSS / CISA KEV)
                </h2>
                <p className="text-xs text-slate-500">
                  Extrai componentes diretos e transitivos dos manifestos reais e correlaciona vulnerabilidades com versão do banco e evidência SHA-256.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {softwares.length > 0 && (
                  <select
                    aria-label="Software para SBOM"
                    value={sbomSwId}
                    onChange={(e) => setSbomSwId(e.target.value)}
                    className="rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs font-medium text-slate-900 dark:text-slate-100"
                  >
                    {softwares.map((sw) => (
                      <option key={sw.id} value={sw.id}>
                        {sw.name} (v{sw.version})
                      </option>
                    ))}
                  </select>
                )}
                <select
                  aria-label="Formato do SBOM"
                  value={sbomFormat}
                  onChange={(e) => setSbomFormat(e.target.value as 'cyclonedx' | 'spdx')}
                  className="rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100"
                >
                  <option value="cyclonedx">CycloneDX 1.5 JSON</option>
                  <option value="spdx">SPDX 2.3 JSON</option>
                </select>
                <button
                  type="button"
                  onClick={handleDownloadSbom}
                  disabled={!sbomData}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-50"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Baixar SBOM JSON</span>
                </button>
              </div>
            </div>

            {sbomLoading ? (
              <div className="p-6 text-xs font-mono text-slate-500">Gerando SBOM e consultando correlações SCA...</div>
            ) : sbomError ? (
              <div className="p-4 rounded-lg border border-amber-500/30 bg-amber-500/10 text-xs text-amber-500">
                {sbomError}
              </div>
            ) : sbomData ? (
              <>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono tabular-nums">
                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                    <div className="text-[10px] font-sans text-slate-500">Componentes</div>
                    <div className="text-xl font-bold text-slate-900 dark:text-slate-100">
                      {sbomData.componentsCount}
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                    <div className="text-[10px] font-sans text-slate-500">Diretos / Transitivos</div>
                    <div className="text-xl font-bold text-[#31d6c4]">
                      {sbomData.directCount} / {sbomData.transitiveCount}
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                    <div className="text-[10px] font-sans text-slate-500">Correlações SCA</div>
                    <div className="text-xl font-bold text-rose-500">
                      {sbomData.scaCorrelations.length}
                    </div>
                  </div>
                  <div className="p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]">
                    <div className="text-[10px] font-sans text-slate-500">SHA-256 ({sbomData.format})</div>
                    <div className="text-xs font-bold text-[#31d6c4] truncate mt-1">
                      {sbomData.documentSha256}
                    </div>
                  </div>
                </div>

                {sbomData.scaCorrelations.length === 0 ? (
                  <div className="p-4 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-xs text-emerald-500 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 shrink-0" />
                    <span>Nenhuma CVE/GHSA conhecida correlacionada aos componentes listados neste pacote.</span>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                          <th className="py-2 pr-3">Pacote &amp; Escopo</th>
                          <th className="py-2 px-3">CVE / GHSA / CWE</th>
                          <th className="py-2 px-3">CVSS / EPSS / KEV</th>
                          <th className="py-2 px-3">Faixa Afetada → Correção</th>
                          <th className="py-2 pl-3">Fonte &amp; Versão DB</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                        {sbomData.scaCorrelations.map((corr) => (
                          <tr key={corr.id}>
                            <td className="py-2.5 pr-3">
                              <div className="font-mono font-bold text-slate-900 dark:text-slate-100">
                                {corr.packageName}@{corr.installedVersion}
                              </div>
                              <div className="text-[11px] text-slate-500">
                                {corr.dependencyScope} · {corr.license}
                              </div>
                            </td>
                            <td className="py-2.5 px-3 font-mono text-[11px]">
                              <div className="font-bold text-rose-500">{corr.cveId || corr.ghsaId}</div>
                              <div className="text-slate-400">{corr.cweIds.join(', ')}</div>
                            </td>
                            <td className="py-2.5 px-3 font-mono text-[11px]">
                              <div>CVSS: {corr.cvssScore ?? 'N/A'}</div>
                              <div className="text-slate-400">
                                EPSS: {corr.epssScore !== null ? `${(corr.epssScore * 100).toFixed(1)}%` : 'N/A'}
                                {corr.cisaKev && (
                                  <span className="ml-1.5 px-1.5 py-0.5 rounded bg-rose-600 text-white text-[10px]">
                                    CISA KEV
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="py-2.5 px-3 font-mono text-[11px]">
                              <div>{corr.affectedVersionRange}</div>
                              <div className="text-emerald-500">Fix: {corr.fixedVersion || 'Sem correção'}</div>
                            </td>
                            <td className="py-2.5 pl-3 font-mono text-[11px] text-slate-500">
                              <div>{corr.dbSource}</div>
                              <div>{corr.dbVersion}</div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            ) : (
              <div className="p-6 text-xs text-slate-500">
                Cadastre um software ou execute um benchmark para gerar e auditar o SBOM.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 5: CONTROLLED EXECUTION & KEY MANAGEMENT */}
      {subTab === 'execution_keys' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Controlled Execution (Tests + HTTP Profiler) */}
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-5">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-[#31d6c4]" />
              <span>Execução Controlada de Testes &amp; Profiler HTTP Real</span>
            </h2>

            {/* Isolated Test Runner */}
            <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-3">
              <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                1. Runner Isolado de Testes (node --test)
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <select
                  aria-label="Software para execução de testes"
                  value={execSwId}
                  onChange={(e) => setExecSwId(e.target.value)}
                  className="flex-1 min-w-[180px] rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
                >
                  {softwares.length === 0 ? (
                    <option value="">Nenhum software cadastrado</option>
                  ) : (
                    softwares.map((sw) => (
                      <option key={sw.id} value={sw.id}>
                        {sw.name} (v{sw.version})
                      </option>
                    ))
                  )}
                </select>
                <button
                  type="button"
                  onClick={handleRunIsolatedTests}
                  disabled={testExecLoading || softwares.length === 0}
                  className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-50"
                >
                  {testExecLoading ? 'Executando...' : 'Executar Testes Isolados'}
                </button>
              </div>
              {testExecResult?.result && (
                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] text-xs font-mono space-y-1">
                  <div className="flex items-center justify-between">
                    <span>Runner: {testExecResult.result.runnerUsed}</span>
                    <span className="text-[#31d6c4] font-bold">
                      Estado: {testExecResult.result.provenance?.state}
                    </span>
                  </div>
                  <div>
                    Aprovados: {testExecResult.result.testsPassed} / {testExecResult.result.testsTotal} · Falhas:{' '}
                    {testExecResult.result.testsFailed}
                  </div>
                  {testExecResult.result.stderrSnippet && (
                    <div className="text-[11px] text-amber-500 font-sans">
                      {testExecResult.result.stderrSnippet}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Real HTTP Load Profiler + Authorized Targets (SSRF Guard) */}
            <div className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                  2. Medição Real de Carga HTTP com SSRF Guard &amp; Alvos Autorizados
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-500">
                  Anti-SSRF Ativo
                </span>
              </div>

              {/* Register New Target */}
              <div className="p-2.5 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] space-y-2 text-xs">
                <div className="text-[11px] font-semibold text-slate-600 dark:text-slate-300">
                  Cadastrar Alvo Autorizado (obrigatório antes de medir carga HTTP)
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <input
                    type="text"
                    aria-label="Rótulo do alvo autorizado"
                    placeholder="Ex.: API Local WinHood"
                    value={newTargetLabel}
                    onChange={(e) => setNewTargetLabel(e.target.value)}
                    className="rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-2.5 py-1.5 text-xs"
                  />
                  <input
                    type="url"
                    aria-label="Origem do alvo autorizado"
                    placeholder="https://alvo.exemplo.com"
                    value={newTargetOrigin}
                    onChange={(e) => setNewTargetOrigin(e.target.value)}
                    className="rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-2.5 py-1.5 font-mono text-xs"
                  />
                  <input
                    type="text"
                    aria-label="Finalidade do alvo autorizado"
                    placeholder="Profiling HTTP controlado"
                    value={newTargetPurpose}
                    onChange={(e) => setNewTargetPurpose(e.target.value)}
                    className="rounded border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-2.5 py-1.5 text-xs"
                  />
                </div>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <label className="flex items-center gap-1.5 text-[11px] text-slate-600 dark:text-slate-400 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={allowLocalhostInTest}
                      onChange={(e) => setAllowLocalhostInTest(e.target.checked)}
                    />
                    <span>Permitir loopback em modo de teste (127.0.0.1 / localhost) para diagnóstico local</span>
                  </label>
                  <button
                    type="button"
                    onClick={handleRegisterPerfTarget}
                    disabled={savingTarget}
                    className="px-3 py-1 rounded text-xs font-semibold bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-950 cursor-pointer disabled:opacity-50"
                  >
                    {savingTarget ? 'Validando...' : 'Autorizar Alvo'}
                  </button>
                </div>
                {targets.length > 0 && (
                  <div className="space-y-1 pt-1">
                    {targets.map((t) => (
                      <div
                        key={t.id}
                        className="flex items-center justify-between gap-2 px-2 py-1 rounded bg-slate-50 dark:bg-[#080b10] font-mono text-[10px]"
                      >
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedTargetId(t.id);
                            setPerfUrl(`${t.origin}/api/health`);
                          }}
                          className={`text-left truncate cursor-pointer ${
                            selectedTargetId === t.id ? 'text-[#31d6c4] font-bold' : 'text-slate-600 dark:text-slate-300'
                          }`}
                        >
                          {t.label} — {t.origin} ({t.purpose} · {t.authorizedBy})
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDeletePerfTarget(t.id)}
                          className="text-rose-500 hover:underline shrink-0 cursor-pointer"
                        >
                          Remover
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                <input
                  type="url"
                  aria-label="URL alvo HTTP para profiling"
                  value={perfUrl}
                  onChange={(e) => setPerfUrl(e.target.value)}
                  className="sm:col-span-3 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-3 py-1.5 font-mono text-slate-900 dark:text-slate-100"
                />
                <input
                  type="number"
                  min={1}
                  max={200}
                  aria-label="Total de requisições"
                  value={perfRequests}
                  onChange={(e) => setPerfRequests(Number(e.target.value))}
                  className="rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-3 py-1.5 font-mono text-slate-900 dark:text-slate-100"
                />
                <input
                  type="number"
                  min={1}
                  max={32}
                  aria-label="Concorrência"
                  value={perfConcurrency}
                  onChange={(e) => setPerfConcurrency(Number(e.target.value))}
                  className="rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-3 py-1.5 font-mono text-slate-900 dark:text-slate-100"
                />
                <button
                  type="button"
                  onClick={handleRunHttpPerf}
                  disabled={perfLoading}
                  className="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-50"
                >
                  {perfLoading ? 'Medindo...' : 'Medir HTTP Real'}
                </button>
              </div>
              {perfResult && (
                <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] text-xs font-mono space-y-1">
                  <div className="flex items-center justify-between">
                    <span>Status: {perfResult.status}</span>
                    <span className="text-[#31d6c4]">{perfResult.throughputRps} req/s</span>
                  </div>
                  <div>
                    P50: {perfResult.p50LatencyMs}ms · P95: {perfResult.p95LatencyMs}ms · P99: {perfResult.p99LatencyMs}ms
                  </div>
                  <div className="text-slate-500">
                    CPU/RSS Agente: {perfResult.agentMetrics?.runnerCpuPercent ?? 0}% /{' '}
                    {perfResult.agentMetrics?.runnerMemoryRssMb ?? 0} MB · Alvo CPU/RAM:{' '}
                    {perfResult.targetMetrics?.cpuPercent ?? 'NÃO MEDIDO'} · Hash:{' '}
                    {perfResult.provenance?.evidenceHash?.slice(0, 14) || 'N/A'}...
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* KeyManagementService */}
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <KeyRound className="w-4 h-4 text-[#31d6c4]" />
                <span>Gestão &amp; Rotação de Chaves Criptográficas (HMAC + Ed25519 + AES-GCM)</span>
              </h2>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#31d6c4]/15 text-[#31d6c4]">
                Zero Segredos Hardcoded
              </span>
            </div>

            {keyStatus && (
              <>
                <div className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] text-xs font-mono space-y-1.5">
                  <div>
                    <span className="text-slate-500">Origem:</span>{' '}
                    <span className="font-bold text-slate-900 dark:text-slate-100">{keyStatus.keyOrigin}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">HMAC Ativa:</span>{' '}
                    <span className="text-[#31d6c4] font-bold">{keyStatus.activeEvidenceKeyId}</span>
                  </div>
                  {keyStatus.activeEd25519KeyId && (
                    <div>
                      <span className="text-slate-500">Ed25519 Assimétrica Ativa:</span>{' '}
                      <span className="text-[#31d6c4] font-bold">{keyStatus.activeEd25519KeyId}</span>
                    </div>
                  )}
                  <div>
                    <span className="text-slate-500">AES-256-GCM Vault Ativa:</span>{' '}
                    <span className="text-[#31d6c4] font-bold">{keyStatus.activeVaultKeyId}</span>
                  </div>
                  <div className="text-[11px] text-slate-400 truncate" title={keyStatus.keystorePath}>
                    Keystore: {keyStatus.keystorePath}
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => handleRotateKey('EVIDENCE_HMAC')}
                    disabled={rotatingKey !== null}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${rotatingKey === 'EVIDENCE_HMAC' ? 'animate-spin' : ''}`} />
                    <span>Rotacionar HMAC</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleRotateKey('EVIDENCE_ED25519')}
                    disabled={rotatingKey !== null}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold border border-[#31d6c4]/50 text-[#0e9f8e] dark:text-[#31d6c4] hover:bg-[#31d6c4]/10 transition-colors cursor-pointer disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${rotatingKey === 'EVIDENCE_ED25519' ? 'animate-spin' : ''}`} />
                    <span>Rotacionar Ed25519</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleRotateKey('TOKEN_VAULT_AES256')}
                    disabled={rotatingKey !== null}
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:border-[#31d6c4] transition-colors cursor-pointer disabled:opacity-50"
                  >
                    <ShieldAlert className="w-3.5 h-3.5 text-[#31d6c4]" />
                    <span>Rotacionar AES-Vault (Re-criptografar)</span>
                  </button>
                </div>

                <div className="overflow-x-auto max-h-64">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                        <th className="py-2 pr-2">Key ID</th>
                        <th className="py-2 px-2">Finalidade</th>
                        <th className="py-2 px-2">Estado</th>
                        <th className="py-2 pl-2">Fingerprint</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60 font-mono text-[11px]">
                      {keyStatus.keys.map((k) => (
                        <tr key={k.keyId}>
                          <td className="py-2 pr-2 font-bold text-slate-900 dark:text-slate-100">
                            {k.keyId}
                          </td>
                          <td className="py-2 px-2 text-slate-500">{k.purpose}</td>
                          <td className="py-2 px-2">
                            <span
                              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                k.status === 'ACTIVE'
                                  ? 'bg-emerald-500/15 text-emerald-500'
                                  : 'bg-amber-500/15 text-amber-500'
                              }`}
                            >
                              {k.status}
                            </span>
                          </td>
                          <td className="py-2 pl-2 text-slate-400">
                            {k.fingerprintSha256.slice(0, 14)}...
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
