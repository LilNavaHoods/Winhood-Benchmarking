import React, { useEffect, useRef, useState } from 'react';
import {
  Clock,
  Command,
  Cpu,
  FileCode2,
  FolderGit2,
  Github,
  Play,
  Search,
  Sliders,
  Sparkles,
  Upload,
  X,
} from 'lucide-react';
import type { Project, Software } from '../types/benchmark';

interface HeaderQuickSearchProps {
  projects: Project[];
  softwares: Software[];
  historicalRuns?: Array<{
    id: string;
    projectName: string;
    profileName: string;
    completedAt: string;
    status: string;
  }>;
  onSelectProject: (projectId: string) => void;
  onSelectSoftware: (softwareId: string) => void;
  onSelectRun: (runId: string) => void;
  onOpenUpload: () => void;
  onOpenGitHub: () => void;
  onOpenWizard: () => void;
}

export const HeaderQuickSearch: React.FC<HeaderQuickSearchProps> = ({
  projects,
  softwares,
  historicalRuns = [],
  onSelectProject,
  onSelectSoftware,
  onSelectRun,
  onOpenUpload,
  onOpenGitHub,
  onOpenWizard,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Keyboard shortcut listener: '/' or 'Ctrl+K' / 'Cmd+K' to focus
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsOpen(true);
        setTimeout(() => inputRef.current?.focus(), 50);
      } else if (e.key === '/' && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
        e.preventDefault();
        setIsOpen(true);
        setTimeout(() => inputRef.current?.focus(), 50);
      } else if (e.key === 'Escape' && isOpen) {
        setIsOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen]);

  // Close when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const trimmed = query.trim().toLowerCase();

  const filteredProjects = projects.filter(
    (p) =>
      p.name.toLowerCase().includes(trimmed) ||
      p.category.toLowerCase().includes(trimmed) ||
      p.objective.toLowerCase().includes(trimmed) ||
      p.id.toLowerCase().includes(trimmed)
  );

  const filteredSoftwares = softwares.filter(
    (s) =>
      s.name.toLowerCase().includes(trimmed) ||
      s.vendor.toLowerCase().includes(trimmed) ||
      s.version.toLowerCase().includes(trimmed) ||
      s.category.toLowerCase().includes(trimmed) ||
      s.languages.some((l) => l.toLowerCase().includes(trimmed)) ||
      s.id.toLowerCase().includes(trimmed)
  );

  const filteredRuns = historicalRuns.filter(
    (r) =>
      r.id.toLowerCase().includes(trimmed) ||
      r.projectName.toLowerCase().includes(trimmed) ||
      r.profileName.toLowerCase().includes(trimmed) ||
      r.status.toLowerCase().includes(trimmed)
  );

  const hasResults =
    filteredProjects.length > 0 || filteredSoftwares.length > 0 || filteredRuns.length > 0;

  return (
    <div ref={containerRef} className="relative flex-1 max-w-md mx-2 lg:mx-4">
      {/* Search Input Box */}
      <div className="relative flex items-center">
        <Search className="absolute left-3 w-4 h-4 text-slate-400 pointer-events-none" />
        <input
          ref={inputRef}
          type="text"
          value={query}
          onFocus={() => setIsOpen(true)}
          onChange={(e) => {
            setQuery(e.target.value);
            if (!isOpen) setIsOpen(true);
          }}
          placeholder="Pesquisar projetos, softwares ou ID de execução... (Ctrl+K)"
          className="w-full pl-9 pr-20 py-1.5 rounded-lg text-xs font-mono bg-slate-100 dark:bg-[#121824] border border-slate-300 dark:border-slate-800 text-slate-900 dark:text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-[#31d6c4] focus:ring-1 focus:ring-[#31d6c4] transition-all"
        />

        <div className="absolute right-2 flex items-center gap-1.5">
          {query ? (
            <button
              type="button"
              onClick={() => {
                setQuery('');
                inputRef.current?.focus();
              }}
              className="p-1 text-slate-400 hover:text-slate-200 cursor-pointer"
              title="Limpar pesquisa"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          ) : (
            <kbd className="hidden sm:inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-200 dark:bg-slate-800 border border-slate-300 dark:border-slate-700">
              <Command className="w-2.5 h-2.5" />K
            </kbd>
          )}
        </div>
      </div>

      {/* Dropdown Overlay */}
      {isOpen && (
        <div className="absolute left-0 w-[500px] max-w-[90vw] mt-2 z-50 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0c1017] shadow-2xl overflow-hidden max-h-[75vh] flex flex-col">
          {/* Quick Actions Bar when search is active */}
          <div className="px-3 py-2 border-b border-slate-200 dark:border-slate-800/80 bg-slate-50 dark:bg-[#080b10] flex items-center justify-between text-xs">
            <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
              Ações Rápidas:
            </span>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => {
                  setIsOpen(false);
                  onOpenUpload();
                }}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 transition-colors cursor-pointer"
              >
                <Upload className="w-3 h-3 text-[#31d6c4]" />
                Upload de Projeto
              </button>
              <button
                type="button"
                onClick={() => {
                  setIsOpen(false);
                  onOpenGitHub();
                }}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-800 border border-slate-300 dark:border-slate-700 transition-colors cursor-pointer"
              >
                <Github className="w-3 h-3 text-indigo-400" />
                Buscar no GitHub
              </button>
            </div>
          </div>

          <div className="overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800/60 p-2 space-y-3">
            {/* If no query or results */}
            {!trimmed && (
              <div className="p-3 text-xs text-slate-500 dark:text-slate-400">
                <p className="font-semibold text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5 text-[#31d6c4]" />
                  Pesquise por qualquer entidade da plataforma:
                </p>
                <ul className="list-disc list-inside space-y-0.5 text-[11px] text-slate-500">
                  <li>Nome ou categoria de projeto (ex: &quot;Cofres&quot;, &quot;Criptografia&quot;)</li>
                  <li>Nome do software ou fabricante (ex: &quot;VaultCore&quot;, &quot;KeeSafe&quot;)</li>
                  <li>Identificador da execução de benchmark (UUID da run)</li>
                </ul>
              </div>
            )}

            {trimmed && !hasResults && (
              <div className="py-8 text-center text-xs text-slate-500 dark:text-slate-400">
                Nenhum projeto, software ou execução encontrada para &quot;<span className="text-slate-200 font-mono">{query}</span>&quot;.
              </div>
            )}

            {/* Matching Projects */}
            {filteredProjects.length > 0 && (
              <div>
                <div className="px-2 py-1 text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
                  <span>Projetos ({filteredProjects.length})</span>
                  <span className="text-[10px] text-slate-500">WinHood Catalog</span>
                </div>
                <div className="space-y-1 mt-1">
                  {filteredProjects.slice(0, 6).map((proj) => (
                    <button
                      key={proj.id}
                      type="button"
                      onClick={() => {
                        setIsOpen(false);
                        onSelectProject(proj.id);
                      }}
                      className="w-full text-left p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/70 transition-colors flex items-start gap-2.5 cursor-pointer group"
                    >
                      <div className="p-1.5 rounded-md bg-[#31d6c4]/10 text-[#31d6c4] mt-0.5 shrink-0 group-hover:bg-[#31d6c4]/20 transition-colors">
                        <FolderGit2 className="w-3.5 h-3.5" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">
                            {proj.name}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400 shrink-0">
                            PROJETO
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                          {proj.category} · {proj.objective}
                        </p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Matching Softwares */}
            {filteredSoftwares.length > 0 && (
              <div>
                <div className="px-2 py-1 text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
                  <span>Softwares &amp; Artefatos ({filteredSoftwares.length})</span>
                  <span className="text-[10px] text-slate-500">Ingeridos</span>
                </div>
                <div className="space-y-1 mt-1">
                  {filteredSoftwares.slice(0, 6).map((sw) => (
                    <button
                      key={sw.id}
                      type="button"
                      onClick={() => {
                        setIsOpen(false);
                        onSelectSoftware(sw.id);
                      }}
                      className="w-full text-left p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/70 transition-colors flex items-start gap-2.5 cursor-pointer group"
                    >
                      <div className="p-1.5 rounded-md bg-indigo-500/10 text-indigo-400 mt-0.5 shrink-0 group-hover:bg-indigo-500/20 transition-colors">
                        <FileCode2 className="w-3.5 h-3.5" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-1.5 truncate">
                            <span className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate">
                              {sw.name}
                            </span>
                            <span className="text-[10px] font-mono text-slate-500 shrink-0">
                              v{sw.version}
                            </span>
                          </div>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-300 shrink-0">
                            SOFTWARE
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate">
                          {sw.vendor} · {sw.languages?.join(', ') || 'Código-fonte'} · {sw.inventory?.totalLinesOfCode || 0} LOC
                        </p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Matching Benchmark Runs */}
            {filteredRuns.length > 0 && (
              <div>
                <div className="px-2 py-1 text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
                  <span>Execuções de Benchmark ({filteredRuns.length})</span>
                  <span className="text-[10px] text-slate-500">Histórico</span>
                </div>
                <div className="space-y-1 mt-1">
                  {filteredRuns.slice(0, 5).map((run) => (
                    <button
                      key={run.id}
                      type="button"
                      onClick={() => {
                        setIsOpen(false);
                        onSelectRun(run.id);
                      }}
                      className="w-full text-left p-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800/70 transition-colors flex items-start gap-2.5 cursor-pointer group"
                    >
                      <div className="p-1.5 rounded-md bg-emerald-500/10 text-emerald-400 mt-0.5 shrink-0 group-hover:bg-emerald-500/20 transition-colors">
                        <Cpu className="w-3.5 h-3.5" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold font-mono text-slate-900 dark:text-slate-100 truncate">
                            {run.id}
                          </span>
                          <span
                            className={`text-[10px] font-mono px-1.5 py-0.5 rounded shrink-0 ${
                              run.status === 'COMPLETED'
                                ? 'bg-emerald-500/15 text-emerald-400'
                                : 'bg-amber-500/15 text-amber-400'
                            }`}
                          >
                            {run.status}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 truncate flex items-center gap-1.5">
                          <span>{run.projectName}</span>
                          <span>·</span>
                          <span>{run.profileName}</span>
                          <span>·</span>
                          <Clock className="w-3 h-3 shrink-0" />
                          <span>{new Date(run.completedAt).toLocaleDateString()}</span>
                        </p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
