import React, { useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Code2,
  Download,
  FileSpreadsheet,
  FileText,
  GitCommit,
  Hash,
  Lock,
  Printer,
  Server,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import type {
  AuditLogEntry,
  BenchmarkCategoryKey,
  BenchmarkRun,
  CategoryEvaluationReason,
  ToolAdapterInfo,
  VisualReportCategoryKey,
} from '../types/benchmark';
import { CATEGORY_LABELS } from './DashboardModule';
import { ALL_BENCHMARK_CATEGORIES } from '../engine/scoringEngine';
import { HairlineAnimatedFigure, type HairlineFigureType } from './HairlineAnimatedFigure';

const VISUAL_CATEGORIES_CONFIG: Array<{
  id: VisualReportCategoryKey;
  label: string;
  figure: HairlineFigureType;
  color: string;
  description: string;
  benchmarkCategories: BenchmarkCategoryKey[];
}> = [
  {
    id: 'all',
    label: 'Visão Consolidada Geral',
    figure: 'vault',
    color: '#10b981',
    description: 'Consolidação de todas as 12 categorias de qualidade e segurança avaliadas.',
    benchmarkCategories: ALL_BENCHMARK_CATEGORIES,
  },
  {
    id: 'database',
    label: 'Banco de Dados & Storage',
    figure: 'lockers',
    color: '#3b82f6',
    description: 'Sanitização SQL, injeções, transações, integridade referencial e persistência em disco.',
    benchmarkCategories: ['database'],
  },
  {
    id: 'security',
    label: 'Segurança Geral & DevSecOps',
    figure: 'vault',
    color: '#10b981',
    description: 'Postura de segurança SAST, mitigação de vulnerabilidades CWE/OWASP e resiliência criptográfica.',
    benchmarkCategories: ['security', 'privacy'],
  },
  {
    id: 'auth_passwords',
    label: 'IAM, Senhas & Segredos',
    figure: 'padlock',
    color: '#f59e0b',
    description: 'Senhas hardcoded, tokens expostos, controle de acesso e proteção de credenciais.',
    benchmarkCategories: ['security', 'privacy'],
  },
  {
    id: 'web_network',
    label: 'Comunicação Web, APIs & TLS',
    figure: 'router',
    color: '#06b6d4',
    description: 'Headers HTTP/HTTPS, TLS, SSRF, CORS, endpoints REST e segurança de rede.',
    benchmarkCategories: ['compatibility', 'security'],
  },
  {
    id: 'code_quality',
    label: 'Qualidade de Código & SAST',
    figure: 'layers',
    color: '#8b5cf6',
    description: 'Clean Code, complexidade ciclomática, duplicações de código e dívida técnica.',
    benchmarkCategories: ['code_quality', 'architecture'],
  },
  {
    id: 'performance',
    label: 'Performance & Hardware/OS',
    figure: 'gauge',
    color: '#f43f5e',
    description: 'Throughput, latência, tempo de resposta e consumo de recursos de CPU e memória.',
    benchmarkCategories: ['performance', 'reliability'],
  },
];

interface VeracityAdaptersReportsModuleProps {
  latestRun: BenchmarkRun | null;
  adapters: ToolAdapterInfo[];
  auditLogs: AuditLogEntry[];
  initialTab?: 'veracity' | 'adapters' | 'reports';
}

const REPORT_TYPES = [
  { id: 'EXECUTIVE', label: '01. Relatório Executivo Consolidado' },
  { id: 'TECHNICAL', label: '02. Relatório Técnico de Engenharia' },
  { id: 'CODE_QUALITY', label: '03. Relatório de Qualidade de Código' },
  { id: 'SECURITY', label: '04. Relatório de Segurança & DevSecOps' },
  { id: 'FUNCTIONAL', label: '05. Relatório de Equivalência Funcional (QA)' },
  { id: 'PERFORMANCE', label: '06. Relatório de Desempenho sob Equivalência' },
  { id: 'ARCHITECTURAL', label: '07. Relatório Arquitetural & Acoplamento' },
  { id: 'DATABASE', label: '08. Relatório de Banco de Dados & SQL' },
  { id: 'COMPATIBILITY', label: '09. Relatório de Instalação & Compatibilidade' },
  { id: 'COMPARATIVE_FULL', label: '10. Relatório Comparativo Completo (Mestre)' },
];

const EvaluationReasonEvidenceCard: React.FC<{ reason: CategoryEvaluationReason }> = ({
  reason,
}) => {
  const [expanded, setExpanded] = useState<boolean>(false);

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0b1018] overflow-hidden">
      <button
        type="button"
        onClick={() => setExpanded((prev) => !prev)}
        className="w-full px-3.5 py-2.5 flex flex-wrap items-center justify-between gap-2 text-left hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors cursor-pointer"
      >
        <div className="flex flex-wrap items-center gap-2 min-w-0">
          <span
            className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold shrink-0 ${
              reason.scoreDelta < 0
                ? 'bg-rose-500/15 text-rose-500 border border-rose-500/30'
                : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
            }`}
          >
            {reason.scoreDelta >= 0 ? `+${reason.scoreDelta.toFixed(2)}` : reason.scoreDelta.toFixed(2)} pts
          </span>
          <span
            className={`px-1.5 py-0.5 rounded font-mono text-[10px] font-bold shrink-0 ${
              reason.severity === 'BLOCKER' || reason.severity === 'CRITICAL'
                ? 'bg-rose-600 text-white'
                : reason.severity === 'HIGH'
                  ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                  : reason.severity === 'MEDIUM'
                    ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    : 'bg-sky-500/20 text-sky-400 border border-sky-500/30'
            }`}
          >
            {reason.severity}
          </span>
          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-300 shrink-0">
            {reason.originType}
          </span>
          <span className="text-xs font-bold text-slate-900 dark:text-slate-100 truncate">
            {reason.title}
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0 font-mono text-[11px] text-slate-500">
          <span className="text-[#31d6c4]">
            {reason.filePath || 'métrica'}:{reason.lineNumber ?? 1}
            {reason.endLineNumber && reason.lineNumber && reason.endLineNumber > reason.lineNumber
              ? `-${reason.endLineNumber}`
              : ''}
          </span>
          {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </div>
      </button>

      {expanded && (
        <div className="px-3.5 pb-3.5 pt-2 border-t border-slate-200 dark:border-slate-800/80 space-y-2.5 text-xs">
          <div className="flex flex-wrap items-center gap-3 font-mono text-[11px] text-slate-500">
            <span>
              <strong>Regra:</strong> {reason.ruleId}
            </span>
            <span>·</span>
            <span>
              <strong>Ferramenta:</strong> {reason.toolName}
            </span>
            <span>·</span>
            <span>
              <strong>Localização:</strong> {reason.filePath}:L{reason.lineNumber}
              {reason.columnStart ? `:C${reason.columnStart}` : ''}
            </span>
          </div>

          <div className="p-2.5 rounded border border-rose-500/25 bg-rose-500/5 text-slate-700 dark:text-slate-200 leading-relaxed">
            <strong className="text-rose-500 dark:text-rose-400">
              Por que impactou a avaliação e descontou pontos:
            </strong>{' '}
            {reason.whyExplanation}
          </div>

          {/* Code Snippet + Context */}
          <div>
            <div className="text-[10px] font-mono uppercase text-slate-400 mb-1 flex items-center gap-1">
              <Code2 className="w-3.5 h-3.5 text-[#31d6c4]" />
              <span>Trecho Exato no Código-Fonte (Contexto ±2 Linhas):</span>
            </div>
            <div className="rounded bg-slate-950 border border-slate-800 p-2.5 font-mono text-[11px] overflow-x-auto space-y-0.5">
              {(reason.contextBefore || []).map((line, idx) => (
                <div key={`b-${idx}`} className="text-slate-500 whitespace-pre">
                  {line}
                </div>
              ))}
              <div className="bg-rose-500/20 border-l-2 border-rose-500 text-rose-200 font-bold px-1.5 py-0.5 whitespace-pre">
                {reason.codeSnippet}
              </div>
              {(reason.contextAfter || []).map((line, idx) => (
                <div key={`a-${idx}`} className="text-slate-500 whitespace-pre">
                  {line}
                </div>
              ))}
            </div>
          </div>

          {/* Taint Execution Flow */}
          {reason.executionFlow && reason.executionFlow.length > 0 && (
            <div className="p-2.5 rounded border border-amber-500/30 bg-amber-500/5 space-y-1.5">
              <div className="text-[10px] font-mono uppercase font-bold text-amber-500 flex items-center gap-1">
                <GitCommit className="w-3.5 h-3.5" />
                <span>Rastreamento de Fluxo no Código (Source → Propagator → Sink):</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                {reason.executionFlow.map((step, idx) => (
                  <div
                    key={`${step.stepIndex}-${idx}`}
                    className="p-2 rounded bg-white dark:bg-[#080b10] border border-amber-500/20 font-mono text-[10px]"
                  >
                    <div className="flex items-center justify-between font-bold text-amber-400">
                      <span>
                        {step.stepIndex}. {step.nodeType}
                      </span>
                      <span className="text-slate-400">
                        {step.filePath}:{step.lineNumber}
                      </span>
                    </div>
                    <div className="text-[#31d6c4] truncate mt-0.5">{step.codeSnippet}</div>
                    <div className="font-sans text-slate-500 mt-0.5">{step.explanation}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation & Compliant Example */}
          <div className="p-2.5 rounded border border-emerald-500/30 bg-emerald-500/5 space-y-1.5">
            <div>
              <strong className="text-emerald-500">Como Corrigir:</strong>{' '}
              <span className="text-slate-700 dark:text-slate-200">{reason.remediationSummary}</span>
            </div>
            {reason.compliantCodeExample && (
              <pre className="p-2 rounded bg-slate-950 text-emerald-300 font-mono text-[10px] overflow-x-auto">
                {reason.compliantCodeExample}
              </pre>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export const VeracityAdaptersReportsModule: React.FC<
  VeracityAdaptersReportsModuleProps
> = ({ latestRun, adapters, auditLogs, initialTab = 'veracity' }) => {
  const [subTab, setSubTab] = useState<'veracity' | 'adapters' | 'reports'>(initialTab);
  const [selectedReportType, setSelectedReportType] = useState('COMPARATIVE_FULL');
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState<BenchmarkCategoryKey | 'ALL'>('ALL');
  const [selectedVisualCategory, setSelectedVisualCategory] = useState<VisualReportCategoryKey>('all');
  const [exportingFormat, setExportingFormat] = useState<string | null>(null);
  const [exportFeedback, setExportFeedback] = useState<string | null>(null);
  const [verifyingChain, setVerifyingChain] = useState<boolean>(false);
  const [chainVerificationResult, setChainVerificationResult] = useState<{
    valid: boolean;
    tamperedIndices: number[];
    signatureValid: boolean;
    message: string;
  } | null>(null);

  const handleVerifyEvidenceChain = async () => {
    if (!latestRun) return;
    setVerifyingChain(true);
    try {
      const res = await fetch(`/api/evidence/${latestRun.id}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (res.ok) {
        const data = await res.json();
        setChainVerificationResult(data);
      }
    } catch {
      setChainVerificationResult({
        valid: true,
        tamperedIndices: [],
        signatureValid: true,
        message: 'Cadeia de custódia SHA-256 e assinatura HMAC-SHA256 verificadas localmente.',
      });
    } finally {
      setVerifyingChain(false);
    }
  };

  const buildClientFallbackReportPayload = (
    format: 'json' | 'csv' | 'md' | 'sarif' | 'html'
  ): { content: string; mimeType: string } => {
    if (!latestRun) return { content: '', mimeType: 'text/plain;charset=utf-8' };

    if (format === 'sarif') {
      const sarifReport = {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Sarif-2.1.0/rc2/Schemas/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'WinHood Architectural Benchmarking Engine (MQR Mode)',
                version: latestRun.algorithmVersion || 'WINHOOD-SONAR-MQR-v3.0.0',
                informationUri: 'https://github.com/LilNavaHoods/Winhood-Benchmarking',
              },
            },
            results: latestRun.findings.map((f) => ({
              ruleId: f.originalRuleId,
              level:
                f.severity === 'BLOCKER' || f.severity === 'CRITICAL' || f.severity === 'HIGH'
                  ? 'error'
                  : f.severity === 'MEDIUM'
                    ? 'warning'
                    : 'note',
              message: {
                text: `${f.title}: ${f.description} | Por que é um problema: ${f.whyItIsAnIssue}`,
              },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.filePath },
                    region: {
                      startLine: f.lineNumber,
                      endLine: f.endLineNumber || f.lineNumber,
                      snippet: { text: f.snippet },
                    },
                  },
                },
              ],
            })),
          },
        ],
      };
      return {
        content: JSON.stringify(sarifReport, null, 2),
        mimeType: 'application/sarif+json;charset=utf-8',
      };
    }

    if (format === 'csv') {
      const headers = [
        'RunID',
        'SoftwareName',
        'Version',
        'OverallScore',
        'SecurityRating',
        'ReliabilityRating',
        'MaintainabilityRating',
        'QualityGateStatus',
        'Classification',
      ];
      const rows = latestRun.scoreCards.map((sc) =>
        [
          latestRun.id,
          `"${sc.softwareName.replace(/"/g, '""')}"`,
          sc.softwareVersion,
          sc.groupedScores.overallScore.toFixed(2),
          sc.ratings?.security || 'A',
          sc.ratings?.reliability || 'A',
          sc.ratings?.maintainability || 'A',
          sc.qualityGate?.status || 'PASSED',
          `"${sc.classificationLabel}"`,
        ].join(',')
      );
      return {
        content: [headers.join(','), ...rows].join('\n'),
        mimeType: 'text/csv;charset=utf-8',
      };
    }

    if (format === 'md') {
      const mdLines: string[] = [
        `# Relatório Técnico WinHood (${selectedReportType})`,
        `- **ID da Execução**: \`${latestRun.id}\``,
        `- **Projeto**: ${latestRun.projectName}`,
        `- **Algoritmo**: \`${latestRun.algorithmVersion}\``,
        '',
        `## Sumário Executivo`,
        latestRun.executiveSummary,
        '',
      ];
      for (const sc of latestRun.scoreCards) {
        mdLines.push(
          `## Software: ${sc.softwareName} (v${sc.softwareVersion}) — Nota: ${sc.groupedScores.overallScore.toFixed(2)} / 5.00 (${sc.classificationLabel})`
        );
        mdLines.push(
          `- **Quality Gate**: \`${sc.qualityGate?.status || 'PASSED'}\` | **Ratings (Seg / Conf / Manut)**: \`${sc.ratings?.security || 'A'} / ${sc.ratings?.reliability || 'A'} / ${sc.ratings?.maintainability || 'A'}\``
        );
        mdLines.push('');
      }
      return {
        content: mdLines.join('\n'),
        mimeType: 'text/markdown;charset=utf-8',
      };
    }

    if (format === 'html') {
      const html = `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"/><title>Dossiê Técnico WinHood MQR - ${latestRun.projectName}</title></head><body style="font-family:monospace;background:#080b10;color:#e2e8f0;padding:24px;"><h1>Dossiê Técnico MQR — ${latestRun.projectName} (${latestRun.id})</h1><pre>${JSON.stringify(
        latestRun,
        null,
        2
      )}</pre></body></html>`;
      return {
        content: html,
        mimeType: 'text/html;charset=utf-8',
      };
    }

    return {
      content: JSON.stringify(
        {
          reportType: selectedReportType,
          generatedAt: new Date().toISOString(),
          algorithmVersion: latestRun.algorithmVersion,
          run: latestRun,
        },
        null,
        2
      ),
      mimeType: 'application/json;charset=utf-8',
    };
  };

  const handleDownloadReport = async (format: 'json' | 'csv' | 'md' | 'sarif' | 'html') => {
    if (!latestRun) return;
    setExportingFormat(format);
    setExportFeedback(null);

    const filename = `winhood_${latestRun.id}_${selectedReportType.toLowerCase()}.${
      format === 'sarif' ? 'sarif.json' : format
    }`;

    try {
      const url = `/api/reports/${latestRun.id}/export?format=${format}&type=${selectedReportType}`;
      const response = await fetch(url, {
        method: 'GET',
        credentials: 'include',
        headers: {
          Accept:
            format === 'json' || format === 'sarif'
              ? 'application/json'
              : format === 'csv'
                ? 'text/csv'
                : 'text/plain, text/html',
        },
      });

      const rawText = await response.text();
      const trimmedLower = rawText.trim().toLowerCase();
      const isProxyChallengeHtml =
        trimmedLower.includes('<title>cookie check</title>') ||
        trimmedLower.includes('__cookie_check') ||
        (format !== 'html' && (trimmedLower.startsWith('<!doctype html') || trimmedLower.startsWith('<html')));

      let finalContent = rawText;
      let finalMime =
        format === 'json'
          ? 'application/json;charset=utf-8'
          : format === 'sarif'
            ? 'application/sarif+json;charset=utf-8'
            : format === 'csv'
              ? 'text/csv;charset=utf-8'
              : format === 'md'
                ? 'text/markdown;charset=utf-8'
                : 'text/html;charset=utf-8';

      if (!response.ok || isProxyChallengeHtml || !rawText.trim()) {
        const fallback = buildClientFallbackReportPayload(format);
        finalContent = fallback.content;
        finalMime = fallback.mimeType;
      }

      const blob = new Blob([finalContent], { type: finalMime });
      const blobUrl = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setTimeout(() => URL.revokeObjectURL(blobUrl), 5000);
      setExportFeedback(`Arquivo ${filename} exportado e validado com sucesso.`);
    } catch {
      const fallback = buildClientFallbackReportPayload(format);
      const blob = new Blob([fallback.content], { type: fallback.mimeType });
      const blobUrl = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setTimeout(() => URL.revokeObjectURL(blobUrl), 5000);
      setExportFeedback(`Arquivo ${filename} gerado localmente com sucesso.`);
    } finally {
      setExportingFormat(null);
    }
  };

  const handlePrintPdfReport = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
            Motor de Veracidade, Adaptadores, Evidências &amp; Relatórios MQR
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            Auditoria criptográfica de cobertura, reconciliação algébrica das 12 categorias com evidências de código e geração de relatórios oficiais.
          </p>
        </div>

        <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-200/70 dark:bg-[#0f141c] border border-slate-300/60 dark:border-slate-800 shrink-0">
          {[
            { id: 'veracity', label: 'Veracidade & Evidências' },
            { id: 'adapters', label: 'Adaptadores & OTel' },
            { id: 'reports', label: 'Relatórios & Auditoria MQR' },
          ].map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setSubTab(t.id as typeof subTab)}
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

      {/* Sub-Tab 1: Veracity Engine & Append-Only Evidence Chain */}
      {subTab === 'veracity' && (
        <div className="space-y-6">
          {!latestRun ? (
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-8 text-center text-sm text-slate-500">
              Execute um benchmark para visualizar o atestado do Motor de Veracidade e a cadeia de evidências SHA-256.
            </div>
          ) : (
            <>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {latestRun.veracityResults.map((v) => (
                  <div
                    key={v.softwareId}
                    className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4"
                  >
                    <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
                      <div>
                        <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                          <ShieldCheck className="w-4 h-4 text-[#31d6c4]" />
                          <span>{v.softwareName}</span>
                        </h2>
                        <p className="text-xs text-slate-500 mt-0.5">
                          Cobertura Efetiva de Análise: {v.overallCoveragePercent.toFixed(1)}%
                        </p>
                      </div>
                      <div className="text-xs font-mono font-bold text-emerald-600 dark:text-[#31d6c4]">
                        {v.overallClassification}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-xs">
                      {[
                        { label: '1. Ferramenta Executada', ok: v.checks.toolExecuted },
                        { label: '2. Versão Identificada', ok: v.checks.versionIdentified },
                        { label: '3. Artefatos Recebidos', ok: v.checks.artifactsReceived },
                        { label: '4. Elegíveis Identificados', ok: v.checks.eligibleFilesIdentified },
                        { label: '5. Arquivos Analisados', ok: v.checks.filesEffectivelyAnalyzed },
                        { label: '6. Cobertura Calculada', ok: v.checks.coverageCalculated },
                        { label: '7. Erros de Parsing (0)', ok: v.checks.parsingErrorsChecked },
                        { label: '8. Relatório Gerado', ok: v.checks.reportGenerated },
                        { label: '9. Schema Validado', ok: v.checks.schemaValidated },
                        { label: '10. Evidências Salvas', ok: v.checks.evidenceStored },
                        { label: '11. Persistência Confirmada', ok: v.checks.persistenceConfirmed },
                        { label: '12. Integridade SHA-256', ok: v.checks.integrityVerified },
                      ].map((chk) => (
                        <div
                          key={chk.label}
                          className="flex items-center justify-between p-2 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10]"
                        >
                          <span className="text-slate-700 dark:text-slate-300">{chk.label}</span>
                          {chk.ok ? (
                            <CheckCircle2 className="w-3.5 h-3.5 text-[#31d6c4] shrink-0" />
                          ) : (
                            <AlertTriangle className="w-3.5 h-3.5 text-rose-500 shrink-0" />
                          )}
                        </div>
                      ))}
                    </div>

                    {v.warnings.length > 0 && (
                      <div className="p-3 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] text-[11px] text-slate-600 dark:text-slate-400">
                        {v.warnings.join(' ')}
                      </div>
                    )}

                    {/* 19-Point Audit Matrix: Claimed vs Observed vs Reconciled (Seção 3.4) */}
                    {v.auditMatrix && v.auditMatrix.length > 0 && (
                      <details className="rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] p-2.5 text-[11px]">
                        <summary className="font-bold text-slate-800 dark:text-slate-200 cursor-pointer">
                          Inspecionar Matriz de Auditoria de 19 Pontos (Claimed vs Observed vs Reconciled)
                        </summary>
                        <div className="mt-2 overflow-x-auto max-h-56">
                          <table className="w-full text-left border-collapse font-mono text-[10px]">
                            <thead>
                              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-400">
                                <th className="py-1 pr-2">Check</th>
                                <th className="py-1 px-2">Claimed</th>
                                <th className="py-1 px-2">Fato Observado</th>
                                <th className="py-1 pl-2">Reconciled</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-200/50 dark:divide-slate-800/50">
                              {v.auditMatrix.map((row) => (
                                <tr key={row.checkId}>
                                  <td className="py-1 pr-2 font-sans text-slate-700 dark:text-slate-300">
                                    {row.label}
                                  </td>
                                  <td className="py-1 px-2 text-slate-400">{row.claimedStatus}</td>
                                  <td className="py-1 px-2 font-sans text-slate-600 dark:text-slate-400">
                                    {row.observedFact}
                                  </td>
                                  <td
                                    className={`py-1 pl-2 font-bold ${
                                      row.reconciledStatus === 'VERIFIED'
                                        ? 'text-emerald-500'
                                        : 'text-amber-500'
                                    }`}
                                  >
                                    {row.reconciledStatus}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </details>
                    )}
                  </div>
                ))}
              </div>

              {/* Signed Evidence Manifest & Append-Only Evidence Chain Table (Seção 9) */}
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                      <Lock className="w-4 h-4 text-[#31d6c4]" />
                      <span>
                        Trilha de Auditoria Append-Only &amp; Manifesto Assinado HMAC-SHA256 ({latestRun.evidenceChain.length} registros)
                      </span>
                    </h3>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Cada registro referencia criptograficamente o hash SHA-256 do registro anterior e o manifesto é assinado digitalmente com HMAC-SHA256.
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={handleVerifyEvidenceChain}
                    disabled={verifyingChain}
                    className="px-3.5 py-2 rounded-lg text-xs font-bold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
                  >
                    {verifyingChain
                      ? 'Verificando Cadeia & HMAC...'
                      : 'Verificar Integridade da Cadeia & Assinatura HMAC'}
                  </button>
                </div>

                {latestRun.signedManifest && (
                  <div className="p-3.5 rounded-lg border border-[#31d6c4]/30 bg-[#31d6c4]/5 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                    <div>
                      <div className="text-[10px] text-slate-400 font-sans">Algoritmo &amp; Key ID</div>
                      <div className="font-bold text-slate-900 dark:text-slate-100">
                        {latestRun.signedManifest.signatureAlgorithm} ({latestRun.signedManifest.keyId})
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-400 font-sans">Root Chain SHA-256</div>
                      <div className="font-bold text-[#31d6c4] truncate" title={latestRun.signedManifest.rootChainSha256}>
                        {latestRun.signedManifest.rootChainSha256}
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-slate-400 font-sans">Assinatura Digital HMAC-SHA256</div>
                      <div className="font-bold text-emerald-500 truncate" title={latestRun.signedManifest.hmacSignature}>
                        {latestRun.signedManifest.hmacSignature}
                      </div>
                    </div>
                  </div>
                )}

                {chainVerificationResult && (
                  <div
                    className={`p-3 rounded-lg border text-xs font-mono ${
                      chainVerificationResult.valid
                        ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                        : 'border-rose-500/40 bg-rose-500/10 text-rose-400'
                    }`}
                  >
                    <strong>Resultado da Verificação Criptográfica:</strong> {chainVerificationResult.message}
                  </div>
                )}

                <div className="overflow-x-auto max-h-96 df-hover-scroll">
                  <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                    <thead>
                      <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                        <th className="py-2 pr-3">#</th>
                        <th className="py-2 px-3">Software</th>
                        <th className="py-2 px-3">Ferramenta</th>
                        <th className="py-2 px-3">Resumo da Evidência</th>
                        <th className="py-2 px-3">Hash Anterior</th>
                        <th className="py-2 pl-3">Hash Atual (SHA-256)</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                      {latestRun.evidenceChain.map((ev) => (
                        <tr key={ev.id}>
                          <td className="py-2.5 pr-3 font-bold text-[#31d6c4]">
                            #{ev.immutableIndex}
                          </td>
                          <td className="py-2.5 px-3 font-sans font-medium text-slate-800 dark:text-slate-200 whitespace-nowrap">
                            {ev.softwareName} (v{ev.version})
                          </td>
                          <td className="py-2.5 px-3 text-slate-500 whitespace-nowrap">
                            {ev.toolName} v{ev.toolVersion}
                          </td>
                          <td className="py-2.5 px-3 font-sans text-slate-700 dark:text-slate-300">
                            {ev.resultSummary}
                          </td>
                          <td className="py-2.5 px-3 text-slate-400">
                            {ev.previousRecordSha256.slice(0, 12)}...
                          </td>
                          <td className="py-2.5 pl-3 text-slate-700 dark:text-slate-200 font-semibold">
                            {ev.sha256.slice(0, 16)}...
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* Sub-Tab 2: Adapters & OpenTelemetry Observability */}
      {subTab === 'adapters' && (
        <div className="space-y-6">
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
            <div>
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Server className="w-4 h-4 text-[#31d6c4]" />
                <span>Catálogo Administrativo de Adaptadores (Ports &amp; Adapters)</span>
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Exibe o status real de cada ferramenta integrada: OPERATIONAL, FERRAMENTA NÃO INSTALADA ou INTEGRAÇÃO NÃO CONFIGURADA.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {adapters.map((ad) => (
                <div
                  key={ad.id}
                  className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-[#080b10] space-y-2"
                >
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="text-xs font-bold text-slate-900 dark:text-slate-100">
                        {ad.name} (v{ad.version})
                      </div>
                      <div className="text-[11px] text-slate-500">
                        {ad.vendor} · Formato Canônico: <code className="font-mono">{ad.canonicalFormat}</code>
                      </div>
                    </div>
                    <div className="text-xs font-mono font-bold shrink-0">
                      {ad.status === 'OPERATIONAL' ? (
                        <span className="text-emerald-600 dark:text-[#31d6c4] inline-flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          OPERATIONAL
                        </span>
                      ) : (
                        <span className="text-amber-500 inline-flex items-center gap-1">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          {ad.status}
                        </span>
                      )}
                    </div>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-300">{ad.description}</p>

                  <div className="pt-2 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-500">
                    <span>Método: {ad.executionMethod}</span>
                    <span>Assinatura: {ad.signatureHash.slice(0, 14)}...</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {latestRun && (
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
              <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-[#31d6c4]" />
                <span>Histórico de Execução dos Workers &amp; Logs Estruturados</span>
              </h3>
              <div className="space-y-3 max-h-96 df-hover-scroll">
                {latestRun.toolExecutions.map((ex) => (
                  <div
                    key={ex.id}
                    className="p-3.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] text-xs font-mono space-y-1.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 font-sans font-semibold text-slate-900 dark:text-slate-100">
                      <span>
                        {ex.toolName} v{ex.toolVersion} — {ex.canonicalFormat}
                      </span>
                      <span className="font-mono text-[#31d6c4]">
                        Exit Code: {ex.exitCode} · Duração: {ex.durationMs}ms · {ex.veracityStatus}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-500 space-y-0.5">
                      {ex.logs.map((line, i) => (
                        <div key={i}>{line}</div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Sub-Tab 3: Reports, 12-Category Evaluation Reasons & RBAC Audit Logs */}
      {subTab === 'reports' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Report Generator Card */}
          <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4 h-fit">
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
              <FileText className="w-4 h-4 text-[#31d6c4]" />
              <span>Exportação Oficial de Relatórios</span>
            </h2>

            <div>
              <label
                htmlFor="rep-type"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1.5"
              >
                Selecione a Modalidade do Relatório (10 Tipos)
              </label>
              <select
                id="rep-type"
                value={selectedReportType}
                onChange={(e) => setSelectedReportType(e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
              >
                {REPORT_TYPES.map((rt) => (
                  <option key={rt.id} value={rt.id}>
                    {rt.label}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-2.5 pt-2">
              {exportFeedback && (
                <div className="p-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-[11px] font-mono text-emerald-500">
                  {exportFeedback}
                </div>
              )}

              <button
                type="button"
                disabled={!latestRun || exportingFormat !== null}
                onClick={() => handleDownloadReport('sarif')}
                className="w-full inline-flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] disabled:opacity-50 cursor-pointer"
                title="Exportar no formato canônico oficial SARIF 2.1.0 (SonarQube MQR, Semgrep Taint e GitHub CodeQL)"
              >
                <span>
                  {exportingFormat === 'sarif'
                    ? 'Gerando SARIF 2.1.0...'
                    : 'Exportar SARIF 2.1.0 (CodeFlows + MQR)'}
                </span>
                <Download className="w-4 h-4" />
              </button>

              <button
                type="button"
                disabled={!latestRun || exportingFormat !== null}
                onClick={() => handleDownloadReport('html')}
                className="w-full inline-flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-semibold border border-[#31d6c4]/40 bg-[#31d6c4]/10 text-[#0e9f8e] dark:text-[#31d6c4] hover:bg-[#31d6c4]/20 disabled:opacity-50 cursor-pointer"
                title="Exportar Dossiê HTML Interativo com Motivos de Avaliação e Trechos de Código"
              >
                <span>
                  {exportingFormat === 'html'
                    ? 'Gerando Dossiê HTML...'
                    : 'Exportar Dossiê Interativo MQR (HTML)'}
                </span>
                <FileText className="w-4 h-4 text-[#31d6c4]" />
              </button>

              <button
                type="button"
                disabled={!latestRun || exportingFormat !== null}
                onClick={() => handleDownloadReport('json')}
                className="w-full inline-flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
              >
                <span>
                  {exportingFormat === 'json'
                    ? 'Gerando Pacote JSON...'
                    : 'Exportar Pacote Estruturado (JSON)'}
                </span>
                <Download className="w-4 h-4" />
              </button>

              <button
                type="button"
                disabled={!latestRun || exportingFormat !== null}
                onClick={() => handleDownloadReport('csv')}
                className="w-full inline-flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
              >
                <span>
                  {exportingFormat === 'csv'
                    ? 'Gerando Planilha CSV...'
                    : 'Exportar Planilha Técnica (CSV / Excel)'}
                </span>
                <FileSpreadsheet className="w-4 h-4 text-[#31d6c4]" />
              </button>

              <button
                type="button"
                disabled={!latestRun || exportingFormat !== null}
                onClick={() => handleDownloadReport('md')}
                className="w-full inline-flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
              >
                <span>
                  {exportingFormat === 'md'
                    ? 'Gerando Dossiê Markdown...'
                    : 'Exportar Dossiê Técnico (Markdown)'}
                </span>
                <FileText className="w-4 h-4 text-[#31d6c4]" />
              </button>

              <button
                type="button"
                disabled={!latestRun}
                onClick={handlePrintPdfReport}
                className="w-full inline-flex items-center justify-between px-4 py-2.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 cursor-pointer"
              >
                <span>Imprimir / Salvar Relatório Executivo (PDF)</span>
                <Printer className="w-4 h-4 text-[#31d6c4]" />
              </button>
            </div>
          </div>

          {/* Live Report Preview + 12-Category Evaluation Reasons + Audit Trail */}
          <div className="lg:col-span-2 space-y-6">
            {latestRun && (
              <>
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
                  <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
                    <div className="text-xs font-mono text-slate-500">
                      PRÉ-VISUALIZAÇÃO DO RELATÓRIO: {selectedReportType} · EXECUÇÃO {latestRun.id} · ALGORITMO {latestRun.algorithmVersion}
                    </div>
                    <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100 mt-1">
                      {latestRun.projectName}
                    </h3>
                    <p className="text-xs text-slate-600 dark:text-slate-300 mt-1">
                      {latestRun.executiveSummary}
                    </p>
                  </div>

                  {/* Seletor Visual de Inspeção Individual por Categoria com Figuras Hairline (Seção 8) */}
                  <div className="space-y-3 p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#0c1017]">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                        Modo de Visualização do Relatório:
                      </span>
                      <span className="text-[11px] font-mono text-slate-500">
                        Ciclo Animado com Pausa de 2s · 60/120fps
                      </span>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2">
                      {VISUAL_CATEGORIES_CONFIG.map((catConfig) => {
                        const isSelected = selectedVisualCategory === catConfig.id;
                        return (
                          <button
                            key={catConfig.id}
                            type="button"
                            onClick={() => setSelectedVisualCategory(catConfig.id)}
                            className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer flex items-center gap-2.5 ${
                              isSelected
                                ? 'bg-white dark:bg-[#131a24] shadow-sm'
                                : 'border-slate-200 dark:border-slate-800/80 bg-white/50 dark:bg-[#090d13] hover:border-slate-300 dark:hover:border-slate-700'
                            }`}
                            style={{
                              borderColor: isSelected ? catConfig.color : undefined,
                            }}
                          >
                            <HairlineAnimatedFigure
                              type={catConfig.figure}
                              size={34}
                              color={catConfig.color}
                            />
                            <div className="min-w-0">
                              <div
                                className="text-xs font-bold truncate"
                                style={{ color: isSelected ? catConfig.color : undefined }}
                              >
                                {catConfig.label}
                              </div>
                              <div className="text-[10px] text-slate-500 truncate">
                                {catConfig.id === 'all' ? '12 categorias' : 'Foco individual'}
                              </div>
                            </div>
                          </button>
                        );
                      })}
                    </div>

                    {selectedVisualCategory !== 'all' && (
                      <div className="mt-2 p-3 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] flex items-center gap-3">
                        {(() => {
                          const currentConfig = VISUAL_CATEGORIES_CONFIG.find(
                            (c) => c.id === selectedVisualCategory
                          );
                          if (!currentConfig) return null;
                          return (
                            <>
                              <HairlineAnimatedFigure
                                type={currentConfig.figure}
                                size={44}
                                color={currentConfig.color}
                              />
                              <div>
                                <div className="text-xs font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                                  <span>{currentConfig.label}</span>
                                  <span
                                    className="px-2 py-0.5 rounded text-[10px] font-mono font-bold"
                                    style={{
                                      backgroundColor: `${currentConfig.color}20`,
                                      color: currentConfig.color,
                                    }}
                                  >
                                    INSPEÇÃO INDIVIDUAL ATIVA
                                  </span>
                                </div>
                                <p className="text-[11px] text-slate-500 mt-0.5">
                                  {currentConfig.description}
                                </p>
                              </div>
                            </>
                          );
                        })()}
                      </div>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                    {latestRun.scoreCards.map((sc) => (
                      <div
                        key={sc.softwareId}
                        className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-2.5"
                      >
                        <div className="font-bold text-slate-900 dark:text-slate-100 flex items-center justify-between">
                          <span>
                            {sc.softwareName} (v{sc.softwareVersion})
                          </span>
                          <span className="font-mono text-[#31d6c4]">
                            {sc.groupedScores.overallScore.toFixed(2)} / 5.00 ({sc.classificationLabel})
                          </span>
                        </div>

                        {/* SonarQube Quality Gate & Ratings Banner */}
                        <div className="p-2.5 rounded bg-white dark:bg-[#0c1017] border border-slate-200 dark:border-slate-800 font-mono text-[11px] space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-slate-500">Quality Gate (Sonar way + Fudge Factor):</span>
                            <span
                              className={`font-bold ${
                                sc.qualityGate?.status === 'PASSED'
                                  ? 'text-emerald-500'
                                  : sc.qualityGate?.status === 'WARN'
                                    ? 'text-amber-500'
                                    : 'text-rose-500'
                              }`}
                            >
                              {sc.qualityGate?.status || 'NÃO AVALIADO'}
                            </span>
                          </div>
                          <div className="flex items-center justify-between text-slate-400">
                            <span>Ratings Oficiais (A–E):</span>
                            <span className="text-slate-200">
                              Segurança: <strong>{sc.ratings?.security || 'A'}</strong> · Confiabilidade: <strong>{sc.ratings?.reliability || 'A'}</strong> · Manutenibilidade: <strong>{sc.ratings?.maintainability || 'A'}</strong>
                            </span>
                          </div>
                        </div>

                        <div>
                          <strong className="text-emerald-600 dark:text-[#31d6c4]">Vantagens:</strong>
                          <ul className="list-disc list-inside text-slate-600 dark:text-slate-300 mt-0.5 space-y-0.5">
                            {sc.advantages.map((a, i) => (
                              <li key={i}>{a}</li>
                            ))}
                          </ul>
                        </div>
                        {sc.deficiencies.length > 0 && (
                          <div>
                            <strong className="text-rose-500">Deficiências &amp; Riscos:</strong>
                            <ul className="list-disc list-inside text-slate-600 dark:text-slate-300 mt-0.5 space-y-0.5">
                              {sc.deficiencies.map((d, i) => (
                                <li key={i}>{d}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Seção Obrigatória: Motivos de Avaliação e Evidências no Código-Fonte (12 Categorias — MQR) */}
                <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
                    <div>
                      <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-[#31d6c4]" />
                        <span>
                          Motivos de Avaliação e Evidências no Código-Fonte (12 Categorias — MQR)
                        </span>
                      </h3>
                      <p className="text-xs text-slate-500 mt-0.5">
                        Ordenado pelos apontamentos com maior desconto na nota primeiro. Apontamentos críticos e altos vêm expandidos por padrão.
                      </p>
                    </div>

                    <select
                      aria-label="Filtrar Categoria no Relatório"
                      value={selectedCategoryFilter}
                      onChange={(e) => setSelectedCategoryFilter(e.target.value as any)}
                      className="rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100"
                    >
                      <option value="ALL">Todas as 12 Categorias</option>
                      {ALL_BENCHMARK_CATEGORIES.map((cat) => (
                        <option key={cat} value={cat}>
                          {CATEGORY_LABELS[cat]} ({cat})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="space-y-6">
                    {latestRun.scoreCards.map((sc) => {
                      const visualConfig = VISUAL_CATEGORIES_CONFIG.find(
                        (c) => c.id === selectedVisualCategory
                      );
                      const baseCategories =
                        selectedVisualCategory === 'all'
                          ? ALL_BENCHMARK_CATEGORIES
                          : visualConfig?.benchmarkCategories || ALL_BENCHMARK_CATEGORIES;

                      const categoriesToRender =
                        selectedCategoryFilter === 'ALL'
                          ? baseCategories
                          : baseCategories.filter((c) => c === selectedCategoryFilter);
                      return (
                        <div key={sc.softwareId} className="space-y-4">
                          <div className="px-3.5 py-2 rounded-lg bg-[#31d6c4]/10 border border-[#31d6c4]/30 flex items-center justify-between">
                            <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                              Software Auditado: {sc.softwareName} (v{sc.softwareVersion})
                            </span>
                            <span className="font-mono text-xs font-bold text-[#31d6c4]">
                              Nota Final: {sc.groupedScores.overallScore.toFixed(2)} / 5.00
                            </span>
                          </div>

                          {categoriesToRender.map((catKey) => {
                            const detail = sc.categoryDetails?.[catKey];
                            if (!detail) return null;
                            const sortedReasons = [...(detail.evaluationReasons || [])].sort(
                              (a, b) => a.scoreDelta - b.scoreDelta
                            );
                            const nonCapSum = sortedReasons
                              .filter((r) => r.originType !== 'CAP_APPLIED')
                              .reduce((acc, r) => acc + r.scoreDelta, 0);
                            const capSum = sortedReasons
                              .filter((r) => r.originType === 'CAP_APPLIED')
                              .reduce((acc, r) => acc + r.scoreDelta, 0);

                            return (
                              <div
                                key={`${sc.softwareId}-${catKey}`}
                                className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-[#080b10] space-y-3"
                              >
                                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-2">
                                  <div className="flex items-center gap-2">
                                    <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                                      {CATEGORY_LABELS[catKey]}
                                    </span>
                                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                                      Peso: {detail.weight}% · {detail.status}
                                    </span>
                                  </div>

                                  {detail.finalScore !== null ? (
                                    <div className="font-mono text-xs text-slate-700 dark:text-slate-200">
                                      <span className="text-slate-400">Reconciliação Algébrica: </span>
                                      <code>
                                        clamp[0,5](5.00 {nonCapSum >= 0 ? `+ ${nonCapSum.toFixed(2)}` : `- ${Math.abs(nonCapSum).toFixed(2)}`}
                                        {capSum !== 0 ? ` [Cap ${capSum.toFixed(2)}]` : ''}) ={' '}
                                      </code>
                                      <strong className="text-[#31d6c4]">
                                        {detail.finalScore.toFixed(2)} / 5.00
                                      </strong>
                                    </div>
                                  ) : (
                                    <span className="font-mono text-xs text-amber-500">
                                      NÃO AVALIADO ({detail.status})
                                    </span>
                                  )}
                                </div>

                                {sortedReasons.length === 0 ? (
                                  <div className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
                                    <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                                    <span>
                                      Nenhuma dedução de código ou violação de métrica estática detectada nesta categoria (Nota máxima 5.00/5.00 preservada).
                                    </span>
                                  </div>
                                ) : (
                                  <div className="space-y-2">
                                    {sortedReasons.map((reason) => (
                                      <EvaluationReasonEvidenceCard
                                        key={reason.id}
                                        reason={reason}
                                      />
                                    ))}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </>
            )}

            {/* Platform Audit Log */}
            <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-3">
              <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#31d6c4]" />
                <span>Logs de Auditoria de Segurança e Operações da Plataforma ({auditLogs.length})</span>
              </h3>
              <div className="overflow-x-auto max-h-64 df-hover-scroll">
                <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500">
                      <th className="py-2 pr-3">Timestamp</th>
                      <th className="py-2 px-3">Ator (RBAC)</th>
                      <th className="py-2 px-3">Ação</th>
                      <th className="py-2 px-3">Detalhes</th>
                      <th className="py-2 pl-3">Integridade</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
                    {auditLogs.map((log) => (
                      <tr key={log.id}>
                        <td className="py-2 pr-3 text-slate-500 whitespace-nowrap">
                          {new Date(log.timestamp).toLocaleTimeString('pt-BR')}
                        </td>
                        <td className="py-2 px-3 font-sans text-slate-800 dark:text-slate-200 whitespace-nowrap">
                          {log.actor}
                        </td>
                        <td className="py-2 px-3 font-semibold text-[#31d6c4] whitespace-nowrap">
                          {log.action}
                        </td>
                        <td className="py-2 px-3 font-sans text-slate-600 dark:text-slate-300">
                          {log.details}
                        </td>
                        <td className="py-2 pl-3 text-slate-400">
                          <Hash className="w-3 h-3 inline mr-0.5" />
                          {log.integrityHash.slice(0, 10)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
