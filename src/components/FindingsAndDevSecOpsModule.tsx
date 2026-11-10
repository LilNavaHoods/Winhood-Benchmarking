import React, { useMemo, useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Code2,
  FileCode,
  Filter,
  Hash,
  Info,
  KeyRound,
  Search,
  ShieldAlert,
} from 'lucide-react';
import type { BenchmarkRun, NormalizedFinding, SeverityLevel } from '../types/benchmark';

interface FindingsAndDevSecOpsModuleProps {
  latestRun: BenchmarkRun | null;
}

export const FindingsAndDevSecOpsModule: React.FC<FindingsAndDevSecOpsModuleProps> = ({
  latestRun,
}) => {
  const [selectedSoftwareId, setSelectedSoftwareId] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedToolId, setSelectedToolId] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedFinding, setSelectedFinding] = useState<NormalizedFinding | null>(null);

  const findings = latestRun?.findings || [];

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (selectedSoftwareId !== 'ALL' && f.softwareId !== selectedSoftwareId) return false;
      if (selectedSeverity !== 'ALL' && f.severity !== selectedSeverity) return false;
      if (selectedCategory !== 'ALL' && f.category !== selectedCategory) return false;
      if (selectedToolId !== 'ALL' && f.toolId !== selectedToolId) return false;
      if (searchQuery.trim().length > 0) {
        const q = searchQuery.toLowerCase();
        const match =
          f.title.toLowerCase().includes(q) ||
          f.filePath.toLowerCase().includes(q) ||
          f.originalRuleId.toLowerCase().includes(q) ||
          (f.cwe && f.cwe.toLowerCase().includes(q)) ||
          (f.cve && f.cve.toLowerCase().includes(q));
        if (!match) return false;
      }
      return true;
    });
  }, [findings, selectedSoftwareId, selectedSeverity, selectedCategory, selectedToolId, searchQuery]);

  const renderSeverityLabel = (sev: SeverityLevel) => {
    switch (sev) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1 font-bold text-rose-600 dark:text-rose-400">
            <AlertOctagon className="w-3.5 h-3.5 shrink-0" />
            CRÍTICO
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1 font-bold text-orange-600 dark:text-orange-400">
            <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
            ALTO
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1 font-semibold text-amber-600 dark:text-amber-400">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            MÉDIO
          </span>
        );
      case 'LOW':
        return (
          <span className="inline-flex items-center gap-1 font-medium text-sky-600 dark:text-sky-400">
            <Info className="w-3.5 h-3.5 shrink-0" />
            BAIXO
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 text-slate-500 dark:text-slate-400">
            <Info className="w-3.5 h-3.5 shrink-0" />
            INFO
          </span>
        );
    }
  };

  if (!latestRun) {
    return (
      <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-8 text-center">
        <p className="text-sm text-slate-500">
          Nenhuma execução de benchmark disponível. Execute um benchmark no Wizard para inspecionar os achados de Qualidade e DevSecOps.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="border-b border-slate-200 dark:border-slate-800 pb-4">
        <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
          Central de Qualidade de Código &amp; Segurança DevSecOps
        </h1>
        <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
          Achados normalizados em SARIF 2.1.0 e CycloneDX 1.5 com correlação CWE/CVE/CVSS, mascaramento automático de segredos e hash SHA-256 por evidência.
        </p>
      </div>

      {/* Comparative Quality & Security Summary Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {latestRun.scoreCards.map((sc) => (
          <div
            key={sc.softwareId}
            className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5"
          >
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  {sc.softwareName} (v{sc.softwareVersion})
                </h2>
                <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  <span>Segurança: {sc.groupedScores.securityScore.toFixed(2)}/5.00</span>
                  <span className="mx-1.5">·</span>
                  <span>Qualidade: {sc.groupedScores.qualityScore.toFixed(2)}/5.00</span>
                </div>
              </div>
              <button
                type="button"
                onClick={() =>
                  setSelectedSoftwareId((prev) =>
                    prev === sc.softwareId ? 'ALL' : sc.softwareId
                  )
                }
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-colors cursor-pointer ${
                  selectedSoftwareId === sc.softwareId
                    ? 'bg-[#31d6c4] text-slate-950'
                    : 'border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300'
                }`}
              >
                {selectedSoftwareId === sc.softwareId ? 'Mostrando Apenas Este' : 'Filtrar Software'}
              </button>
            </div>

            <div className="grid grid-cols-3 sm:grid-cols-6 gap-2.5 mt-4 text-xs font-mono tabular-nums">
              <div>
                <div className="text-slate-400 font-sans text-[11px]">Críticas</div>
                <div className="font-bold text-rose-500 text-sm">{sc.metricsSummary.criticalVulns}</div>
              </div>
              <div>
                <div className="text-slate-400 font-sans text-[11px]">Segredos</div>
                <div className="font-bold text-rose-500 text-sm">{sc.metricsSummary.secretsExposed}</div>
              </div>
              <div>
                <div className="text-slate-400 font-sans text-[11px]">Bugs</div>
                <div className="font-bold text-amber-500 text-sm">{sc.metricsSummary.bugs}</div>
              </div>
              <div>
                <div className="text-slate-400 font-sans text-[11px]">Code Smells</div>
                <div className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                  {sc.metricsSummary.codeSmells}
                </div>
              </div>
              <div>
                <div className="text-slate-400 font-sans text-[11px]">Ciclomática</div>
                <div className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                  {sc.metricsSummary.avgCyclomaticComplexity}
                </div>
              </div>
              <div>
                <div className="text-slate-400 font-sans text-[11px]">Dívida Técnica</div>
                <div className="font-bold text-slate-900 dark:text-slate-100 text-sm">
                  {sc.metricsSummary.technicalDebtMinutes}m
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Filters Toolbar */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          <div>
            <label
              htmlFor="flt-search"
              className="block text-[11px] font-semibold text-slate-500 mb-1"
            >
              Buscar por Regra, Arquivo, CWE ou CVE
            </label>
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
              <input
                id="flt-search"
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Ex: CWE-89, sql, masterKey..."
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] pl-8 pr-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="flt-software"
              className="block text-[11px] font-semibold text-slate-500 mb-1"
            >
              Software Analisado
            </label>
            <select
              id="flt-software"
              value={selectedSoftwareId}
              onChange={(e) => setSelectedSoftwareId(e.target.value)}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
            >
              <option value="ALL">Todos os Softwares</option>
              {latestRun.scoreCards.map((sc) => (
                <option key={sc.softwareId} value={sc.softwareId}>
                  {sc.softwareName}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label
              htmlFor="flt-sev"
              className="block text-[11px] font-semibold text-slate-500 mb-1"
            >
              Severidade
            </label>
            <select
              id="flt-sev"
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
            >
              <option value="ALL">Todas as Severidades</option>
              <option value="CRITICAL">CRITICAL (Crítico)</option>
              <option value="HIGH">HIGH (Alto)</option>
              <option value="MEDIUM">MEDIUM (Médio)</option>
              <option value="LOW">LOW (Baixo)</option>
              <option value="INFO">INFO (Informativo)</option>
            </select>
          </div>

          <div>
            <label
              htmlFor="flt-cat"
              className="block text-[11px] font-semibold text-slate-500 mb-1"
            >
              Categoria de Análise
            </label>
            <select
              id="flt-cat"
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
            >
              <option value="ALL">Todas as Categorias</option>
              <option value="SAST">SAST (Segurança Estática)</option>
              <option value="SECRETS">SECRETS (Segredos Expostos)</option>
              <option value="SCA">SCA (Dependências Vulneráveis)</option>
              <option value="CODE_QUALITY">CODE_QUALITY (Qualidade)</option>
              <option value="ARCHITECTURE">ARCHITECTURE (Arquitetura)</option>
              <option value="DATABASE">DATABASE (Banco de Dados SQL)</option>
            </select>
          </div>

          <div>
            <label
              htmlFor="flt-tool"
              className="block text-[11px] font-semibold text-slate-500 mb-1"
            >
              Ferramenta de Origem
            </label>
            <select
              id="flt-tool"
              value={selectedToolId}
              onChange={(e) => setSelectedToolId(e.target.value)}
              className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs text-slate-900 dark:text-slate-100"
            >
              <option value="ALL">Todas as Ferramentas</option>
              <option value="opengrep-sast">Opengrep SAST Engine</option>
              <option value="gitleaks-secrets">Gitleaks Secret Scanner</option>
              <option value="sonarqube-quality">SonarQube Static Analyzer</option>
              <option value="syft-grype-sca">Syft SBOM &amp; Grype SCA</option>
              <option value="archunit-cruiser">Dependency Cruiser &amp; ArchUnit</option>
              <option value="sqlfluff-db">SQLFluff &amp; Schema Auditor</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table + Evidence Detail Split */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
            <span className="text-xs font-bold text-slate-800 dark:text-slate-200">
              Achados Normalizados e Validados ({filteredFindings.length})
            </span>
            <span className="text-[11px] text-slate-500">
              Clique em um achado para inspecionar a evidência SHA-256
            </span>
          </div>

          <div className="overflow-x-auto max-h-[540px] df-hover-scroll">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-50 dark:bg-[#080b10] text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800">
                  <th className="py-2.5 px-4">Severidade</th>
                  <th className="py-2.5 px-3">Software</th>
                  <th className="py-2.5 px-3">Achado &amp; Regra Original</th>
                  <th className="py-2.5 px-3">Localização</th>
                  <th className="py-2.5 px-3 text-right">CWE / CVSS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {filteredFindings.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500">
                      Nenhum achado encontrado para os filtros selecionados dentro do escopo analisado.
                    </td>
                  </tr>
                ) : (
                  filteredFindings.map((f) => {
                    const isSelected = selectedFinding?.id === f.id;
                    return (
                      <tr
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className={`cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-[#31d6c4]/10'
                            : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                        }`}
                      >
                        <td className="py-3 px-4 font-mono whitespace-nowrap">
                          {renderSeverityLabel(f.severity)}
                        </td>
                        <td className="py-3 px-3 font-medium text-slate-800 dark:text-slate-200 whitespace-nowrap">
                          {f.softwareName}
                        </td>
                        <td className="py-3 px-3">
                          <div className="font-semibold text-slate-900 dark:text-slate-100">
                            {f.title}
                          </div>
                          <div className="text-[11px] font-mono text-slate-500 mt-0.5">
                            <span>{f.category}</span>
                            <span className="mx-1.5">·</span>
                            <span>{f.originalRuleId}</span>
                            <span className="mx-1.5">·</span>
                            <span>{f.toolName}</span>
                          </div>
                        </td>
                        <td className="py-3 px-3 font-mono tabular-nums text-slate-600 dark:text-slate-300 whitespace-nowrap">
                          {f.filePath}:{f.lineNumber}
                        </td>
                        <td className="py-3 px-3 text-right font-mono tabular-nums whitespace-nowrap">
                          <div>{f.cwe || f.cve || '—'}</div>
                          {f.cvss && (
                            <div className="text-[11px] text-rose-500 font-bold">
                              CVSS {f.cvss.toFixed(1)}
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Evidence Inspector Panel */}
        <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 h-fit space-y-4">
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
            <FileCode className="w-4 h-4 text-[#31d6c4]" />
            <span>Inspetor de Evidência &amp; Remediação</span>
          </h3>

          {!selectedFinding && !filteredFindings[0] ? (
            <p className="text-xs text-slate-500">
              Selecione qualquer linha na tabela ao lado para inspecionar o trecho de código e o hash SHA-256 da evidência.
            </p>
          ) : (
            (() => {
              const item = selectedFinding || filteredFindings[0];
              return (
                <div className="space-y-3.5 text-xs">
                  <div>
                    <div className="flex items-center justify-between">
                      {renderSeverityLabel(item.severity)}
                      <span className="font-mono text-slate-500">{item.validationStatus}</span>
                    </div>
                    <h4 className="text-sm font-bold text-slate-900 dark:text-slate-100 mt-2">
                      {item.title}
                    </h4>
                    <p className="text-slate-600 dark:text-slate-300 mt-1 leading-relaxed">
                      {item.description}
                    </p>
                  </div>

                  <div className="p-3 rounded bg-slate-100 dark:bg-[#080b10] font-mono tabular-nums space-y-1 text-[11px]">
                    <div>
                      <strong>Software:</strong> {item.softwareName} (v{item.softwareVersion})
                    </div>
                    <div>
                      <strong>Ferramenta:</strong> {item.toolName} v{item.toolVersion}
                    </div>
                    <div>
                      <strong>Regra:</strong> {item.originalRuleId}
                    </div>
                    <div>
                      <strong>Arquivo:</strong> {item.filePath} (Linha {item.lineNumber})
                    </div>
                    {(item.cwe || item.cve || item.cvss) && (
                      <div>
                        <strong>Referências:</strong> {[item.cwe, item.cve, item.cvss ? `CVSS ${item.cvss}` : null].filter(Boolean).join(' · ')}
                      </div>
                    )}
                  </div>

                  <div>
                    <div className="font-semibold text-slate-700 dark:text-slate-300 mb-1 flex items-center justify-between">
                      <span>Evidência no Código-Fonte (Segredos Mascarados)</span>
                      <KeyRound className="w-3.5 h-3.5 text-[#31d6c4]" />
                    </div>
                    <pre className="p-3 rounded bg-slate-950 text-[#31d6c4] font-mono text-[11px] overflow-x-auto">
                      {item.snippet}
                    </pre>
                  </div>

                  <div>
                    <div className="font-semibold text-slate-700 dark:text-slate-300 mb-1">
                      Recomendação Técnica de Correção
                    </div>
                    <p className="p-3 rounded border border-emerald-500/30 bg-emerald-500/5 text-slate-700 dark:text-slate-200 leading-relaxed">
                      {item.remediation}
                    </p>
                  </div>

                  <div className="pt-2 border-t border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-500 break-all">
                    <Hash className="w-3 h-3 inline mr-1 text-[#31d6c4]" />
                    <strong>Evidence SHA-256:</strong> {item.evidenceSha256}
                  </div>
                </div>
              );
            })()
          )}
        </div>
      </div>
    </div>
  );
};
