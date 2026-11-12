import React, { useEffect, useState } from 'react';
import {
  CheckCircle2,
  ExternalLink,
  FolderGit2,
  GitFork,
  Github,
  Loader2,
  Search,
  Sparkles,
  Star,
  Tag,
  X,
} from 'lucide-react';
import type { Project } from '../types/benchmark';

interface GitHubRepoItem {
  id: number;
  name: string;
  fullName: string;
  owner: string;
  ownerAvatarUrl: string;
  description: string;
  htmlUrl: string;
  cloneUrl: string;
  stars: number;
  forks: number;
  openIssues: number;
  language: string;
  topics: string[];
  license: string;
  defaultBranch: string;
  updatedAt: string;
}

interface GitHubSearchModalProps {
  isOpen: boolean;
  projects: Project[];
  onClose: () => void;
  onSuccess: () => Promise<void>;
  onNotify: (msg: string, type?: 'success' | 'error') => void;
}

const POPULAR_QUERIES = [
  'password manager',
  'keepass',
  'vault',
  'cryptography',
  'devsecops',
  'zero-trust',
  'authentication',
];

export const GitHubSearchModal: React.FC<GitHubSearchModalProps> = ({
  isOpen,
  projects,
  onClose,
  onSuccess,
  onNotify,
}) => {
  const [searchTerm, setSearchTerm] = useState('password manager');
  const [loading, setLoading] = useState(false);
  const [importingId, setImportingId] = useState<number | null>(null);
  const [repos, setRepos] = useState<GitHubRepoItem[]>([]);
  const [sourceNote, setSourceNote] = useState<string>('');

  // Target project selection state
  const [selectedProjectId, setSelectedProjectId] = useState<string>('NEW');
  const [customProjectName, setCustomProjectName] = useState<string>('');

  const fetchGitHubRepos = async (query: string) => {
    setLoading(true);
    try {
      const res = await fetch(`/api/github/search?q=${encodeURIComponent(query)}`);
      const data = await res.json();
      if (res.ok && data.items) {
        setRepos(data.items);
        setSourceNote(
          data.source === 'LIVE_GITHUB_API'
            ? 'Resultados em tempo real via GitHub Search API v3'
            : 'Catálogo curado de benchmarks de segurança open-source'
        );
      } else {
        onNotify('Falha ao consultar repositórios do GitHub.', 'error');
      }
    } catch {
      onNotify('Erro de conexão com o serviço de busca GitHub.', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      void fetchGitHubRepos(searchTerm);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchTerm.trim()) return;
    void fetchGitHubRepos(searchTerm.trim());
  };

  const handleImportRepo = async (repo: GitHubRepoItem) => {
    setImportingId(repo.id);
    try {
      const res = await fetch('/api/github/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: selectedProjectId === 'NEW' ? undefined : selectedProjectId,
          newProjectName: customProjectName || `Benchmark ${repo.name}`,
          projectCategory: 'Gerenciadores de Senhas & Criptografia',
          repoFullName: repo.fullName,
          repoName: repo.name,
          owner: repo.owner,
          description: repo.description,
          htmlUrl: repo.htmlUrl,
          cloneUrl: repo.cloneUrl,
          language: repo.language,
          license: repo.license,
          stars: repo.stars,
          forks: repo.forks,
          defaultBranch: repo.defaultBranch,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || data.message || 'Falha ao importar repositório.', 'error');
        setImportingId(null);
        return;
      }

      onNotify(
        `Repositório "${repo.fullName}" importado com sucesso no projeto "${data.project.name}"!`,
        'success'
      );
      await onSuccess();
      onClose();
    } catch {
      onNotify('Erro ao importar repositório.', 'error');
    } finally {
      setImportingId(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-white dark:bg-[#0c1017] border border-slate-200 dark:border-slate-800 rounded-2xl max-w-3xl w-full shadow-2xl flex flex-col max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-[#080b10]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/15 text-indigo-400 flex items-center justify-center">
              <Github className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                Pesquisa &amp; Ingestão de Projetos GitHub
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Localize repositórios abertos no GitHub para benchmarking comparativo e auditoria estática.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Search Bar & Quick Categories */}
        <div className="p-6 border-b border-slate-200 dark:border-slate-800 space-y-3 bg-white dark:bg-[#0c1017]">
          <form onSubmit={handleSearchSubmit} className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 w-4 h-4 text-slate-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Pesquisar por palavras-chave ou owner/repo (ex: keepassxc, bitwarden, vault)..."
                className="w-full pl-9 pr-3 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-[#31d6c4]"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] font-semibold text-xs transition-colors cursor-pointer shrink-0 inline-flex items-center gap-1.5 disabled:opacity-60"
            >
              {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
              Pesquisar
            </button>
          </form>

          {/* Quick Filter Queries */}
          <div className="flex items-center gap-1.5 flex-wrap text-[11px]">
            <span className="text-slate-500 font-medium">Sugestões:</span>
            {POPULAR_QUERIES.map((q) => (
              <button
                key={q}
                type="button"
                onClick={() => {
                  setSearchTerm(q);
                  void fetchGitHubRepos(q);
                }}
                className={`px-2 py-0.5 rounded-md border text-[11px] transition-colors cursor-pointer ${
                  searchTerm === q
                    ? 'border-[#31d6c4] bg-[#31d6c4]/10 text-[#31d6c4]'
                    : 'border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:border-slate-400'
                }`}
              >
                {q}
              </button>
            ))}
          </div>

          {/* Destination Project Selection */}
          <div className="pt-2 flex flex-col sm:flex-row sm:items-center gap-3 text-xs bg-slate-50 dark:bg-[#080b10] p-2.5 rounded-xl border border-slate-200 dark:border-slate-800">
            <span className="font-semibold text-slate-700 dark:text-slate-300 shrink-0">
              Destino da Importação:
            </span>
            <select
              value={selectedProjectId}
              onChange={(e) => setSelectedProjectId(e.target.value)}
              className="flex-1 px-2.5 py-1 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs font-mono"
            >
              <option value="NEW">+ Criar Novo Projeto com o Nome do Repositório</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  Vincular ao Projeto Existente: {p.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Results List */}
        <div className="flex-1 overflow-y-auto p-6 divide-y divide-slate-100 dark:divide-slate-800/80">
          {sourceNote && (
            <div className="pb-3 text-[11px] text-slate-500 flex items-center justify-between">
              <span>{sourceNote}</span>
              <span>{repos.length} repositórios listados</span>
            </div>
          )}

          {loading ? (
            <div className="py-16 text-center text-xs text-slate-500 flex flex-col items-center gap-2">
              <Loader2 className="w-6 h-6 animate-spin text-[#31d6c4]" />
              <span>Consultando repositórios no GitHub...</span>
            </div>
          ) : repos.length === 0 ? (
            <div className="py-16 text-center text-xs text-slate-500">
              Nenhum repositório encontrado para a pesquisa informada.
            </div>
          ) : (
            repos.map((repo) => (
              <div
                key={repo.id}
                className="py-4 first:pt-0 last:pb-0 flex flex-col sm:flex-row sm:items-start justify-between gap-4 group"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-sm text-slate-900 dark:text-slate-100 group-hover:text-[#31d6c4] transition-colors">
                      {repo.fullName}
                    </span>
                    <a
                      href={repo.htmlUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-1 text-slate-400 hover:text-slate-200 transition-colors"
                      title="Abrir no GitHub"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                      {repo.language}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      {repo.license}
                    </span>
                  </div>

                  <p className="text-xs text-slate-600 dark:text-slate-300 line-clamp-2 leading-relaxed">
                    {repo.description || 'Sem descrição fornecida pelo repositório.'}
                  </p>

                  <div className="flex items-center gap-4 text-[11px] text-slate-500 font-mono">
                    <span className="flex items-center gap-1 text-amber-400">
                      <Star className="w-3.5 h-3.5 fill-amber-400" />
                      {repo.stars.toLocaleString()}
                    </span>
                    <span className="flex items-center gap-1">
                      <GitFork className="w-3.5 h-3.5" />
                      {repo.forks.toLocaleString()}
                    </span>
                    <span>Branch: {repo.defaultBranch}</span>
                  </div>

                  {repo.topics && repo.topics.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap pt-1">
                      {repo.topics.slice(0, 5).map((topic) => (
                        <span
                          key={topic}
                          className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-500"
                        >
                          #{topic}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="shrink-0 pt-1 sm:pt-0">
                  <button
                    type="button"
                    onClick={() => handleImportRepo(repo)}
                    disabled={importingId === repo.id}
                    className="w-full sm:w-auto inline-flex items-center justify-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-60"
                  >
                    {importingId === repo.id ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        Importando...
                      </>
                    ) : (
                      <>
                        <FolderGit2 className="w-3.5 h-3.5" />
                        Importar para WinHood
                      </>
                    )}
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
