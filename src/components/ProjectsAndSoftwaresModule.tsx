import React, { useState } from 'react';
import {
  CheckCircle2,
  Code,
  Edit3,
  FileCode2,
  FolderGit2,
  Github,
  Hash,
  Layers,
  Plus,
  ShieldCheck,
  Trash2,
  Upload,
} from 'lucide-react';
import type { Project, Software } from '../types/benchmark';

interface ProjectsAndSoftwaresModuleProps {
  projects: Project[];
  softwares: Software[];
  onRefresh: () => Promise<void>;
  onNotify: (msg: string, type?: 'success' | 'error') => void;
  onOpenUpload?: () => void;
  onOpenGitHub?: () => void;
}

const PROJECT_CATEGORIES = [
  'Gerenciadores de Senhas & Criptografia',
  'VPN & Segurança de Rede',
  'Sistemas de Chamados (ITSM)',
  'Ferramentas de Monitoramento & Observabilidade',
  'Aplicações Desktop Windows',
  'Aplicações Web & APIs Corporativas',
  'Aplicações Mobile',
  'Ferramentas de Infraestrutura & Cloud',
];

export const ProjectsAndSoftwaresModule: React.FC<ProjectsAndSoftwaresModuleProps> = ({
  projects,
  softwares,
  onRefresh,
  onNotify,
  onOpenUpload,
  onOpenGitHub,
}) => {
  const [subTab, setSubTab] = useState<'projects' | 'softwares'>('projects');

  // Project Form State
  const [editingProject, setEditingProject] = useState<Project | null>(null);
  const [projName, setProjName] = useState('');
  const [projDomainTags, setProjDomainTags] = useState('devsecops, sonarqube-mqr, security, clean-code');
  const [projQualityGateId, setProjQualityGateId] = useState('qg-sonar-way-mqr');
  const [projObjective, setProjObjective] = useState('');
  const [projDescription, setProjDescription] = useState('');
  const [projOwner, setProjOwner] = useState('Engenharia de Segurança & Arquitetura');
  const [confirmDeleteProject, setConfirmDeleteProject] = useState<Project | null>(null);

  // Software Form State
  const [swProjectId, setSwProjectId] = useState(projects[0]?.id || '');
  const [swName, setSwName] = useState('');
  const [swVendor, setSwVendor] = useState('');
  const [swVersion, setSwVersion] = useState('1.0.0');
  const [swDomainTags, setSwDomainTags] = useState('typescript, cryptography, zero-knowledge, kdbx');
  const [swArchitecture, setSwArchitecture] = useState('Clean / Hexagonal Architecture');
  const [swOs, setSwOs] = useState('Windows 11 / Linux');
  const [swDistribution, setSwDistribution] = useState('Open-Source Auditável');
  const [swLicense, setSwLicense] = useState('Apache-2.0');
  const [swSourceType, setSwSourceType] = useState<Software['sourceType']>('GIT_REPO');
  const [swRepoUrl, setSwRepoUrl] = useState('');
  const [swOfficialUrl, setSwOfficialUrl] = useState('');
  const [swDocUrl, setSwDocUrl] = useState('');
  const [swCommitHash, setSwCommitHash] = useState('');
  const [swDescription, setSwDescription] = useState('');
  const [swCustomFileName, setSwCustomFileName] = useState('src/core/securityService.ts');
  const [swCustomFileContent, setSwCustomFileContent] = useState(
    `import crypto from 'node:crypto';\n\nexport function deriveKeySafe(secret: string, salt: Buffer): Buffer {\n  return crypto.pbkdf2Sync(secret, salt, 600000, 32, 'sha512');\n}\n`
  );

  // Selected Software for Inventory / Source Code Modal Inspection
  const [inspectedSoftware, setInspectedSoftware] = useState<Software | null>(null);
  const [ingestFileName, setIngestFileName] = useState('src/module/customCheck.ts');
  const [ingestFileContent, setIngestFileContent] = useState(
    `export function validateInputStrict(value: string): boolean {\n  return value.trim().length > 0;\n}\n`
  );

  const handleSaveProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projName.trim() || !projObjective.trim()) {
      onNotify('Preencha Nome e Objetivo do projeto.', 'error');
      return;
    }

    const parsedTags = projDomainTags
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);

    try {
      const url = editingProject ? `/api/projects/${editingProject.id}` : '/api/projects';
      const method = editingProject ? 'PUT' : 'POST';
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: projName,
          domainTags: parsedTags.length > 0 ? parsedTags : ['multi-category', 'sonarqube-mqr'],
          defaultQualityGateId: projQualityGateId,
          defaultQualityProfileIds: ['sonar-way-ts-mqr-2026', 'sonar-way-sql-mqr-2026'],
          objective: projObjective,
          description: projDescription,
          owner: projOwner,
        }),
      });
      const payload = await res.json();
      if (!res.ok) {
        onNotify(payload.message || payload.error || 'Falha ao salvar projeto.', 'error');
        return;
      }
      onNotify(
        editingProject
          ? `Projeto "${projName}" atualizado com sucesso.`
          : `Projeto "${projName}" cadastrado com UUID ${payload.project.id} (12 categorias habilitadas).`,
        'success'
      );
      setEditingProject(null);
      setProjName('');
      setProjObjective('');
      setProjDescription('');
      await onRefresh();
    } catch {
      onNotify('Erro de comunicação com o servidor ao salvar projeto.', 'error');
    }
  };

  const handleDeleteProjectConfirmed = async () => {
    if (!confirmDeleteProject) return;
    try {
      const res = await fetch(`/api/projects/${confirmDeleteProject.id}`, {
        method: 'DELETE',
      });
      const payload = await res.json();
      if (!res.ok) {
        onNotify(payload.message || payload.error || 'Falha ao excluir projeto.', 'error');
        return;
      }
      onNotify(`Projeto "${confirmDeleteProject.name}" excluído.`, 'success');
      setConfirmDeleteProject(null);
      await onRefresh();
    } catch {
      onNotify('Erro ao excluir projeto.', 'error');
    }
  };

  const handleCreateSoftware = async (e: React.FormEvent) => {
    e.preventDefault();
    const targetProjId = swProjectId || projects[0]?.id;
    if (!targetProjId) {
      onNotify('Crie um projeto antes de cadastrar softwares.', 'error');
      return;
    }
    if (!swName.trim() || !swVendor.trim() || !swVersion.trim()) {
      onNotify('Preencha Nome, Fabricante e Versão do software.', 'error');
      return;
    }

    try {
      const customFilesMap: Record<string, string> = {
        'package.json': JSON.stringify(
          {
            name: swName.toLowerCase().replace(/\s+/g, '-'),
            version: swVersion,
            dependencies: { argon2: '0.41.1' },
          },
          null,
          2
        ),
        'README.md': `# ${swName} v${swVersion}\n${swDescription || 'Documentação técnica verificada.'}`,
      };
      if (swCustomFileName.trim() && swCustomFileContent.trim()) {
        customFilesMap[swCustomFileName.trim()] = swCustomFileContent;
      }

      const parsedSwTags = swDomainTags
        .split(',')
        .map((t) => t.trim())
        .filter(Boolean);

      const res = await fetch('/api/softwares', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: targetProjId,
          name: swName,
          vendor: swVendor,
          version: swVersion,
          domainTags: parsedSwTags.length > 0 ? parsedSwTags : ['multi-category', 'sonarqube-mqr'],
          architecture: swArchitecture,
          operatingSystem: swOs,
          distributionModel: swDistribution,
          licenseType: swLicense,
          sourceType: swSourceType,
          repositoryUrl: swRepoUrl,
          officialUrl: swOfficialUrl,
          documentationUrl: swDocUrl,
          commitHash: swCommitHash,
          description: swDescription,
          customFilesMap,
        }),
      });
      const payload = await res.json();
      if (!res.ok) {
        onNotify(payload.message || payload.error || 'Falha ao cadastrar software.', 'error');
        return;
      }
      onNotify(
        `Software "${swName} v${swVersion}" ingerido com Hash SHA-256: ${payload.software.packageSha256.slice(0, 16)}...`,
        'success'
      );
      setSwName('');
      setSwVendor('');
      setSwDescription('');
      await onRefresh();
    } catch {
      onNotify('Erro ao cadastrar software.', 'error');
    }
  };

  const handleIngestAdditionalFile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inspectedSoftware) return;
    if (!ingestFileName.trim() || !ingestFileContent.trim()) {
      onNotify('Informe o caminho do arquivo e seu conteúdo para ingestão.', 'error');
      return;
    }

    try {
      const res = await fetch(`/api/softwares/${inspectedSoftware.id}/ingest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filesMap: {
            [ingestFileName.trim()]: ingestFileContent,
          },
        }),
      });
      const payload = await res.json();
      if (!res.ok) {
        onNotify(payload.message || payload.error || 'Falha na ingestão.', 'error');
        return;
      }
      setInspectedSoftware(payload.software);
      onNotify(
        `Arquivo "${ingestFileName}" ingerido na área isolada. Novo SHA-256 calculado.`,
        'success'
      );
      await onRefresh();
    } catch {
      onNotify('Erro ao ingerir artefato.', 'error');
    }
  };

  return (
    <div className="space-y-6">
      {/* Module Header & Sub-Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100">
            Projetos, Softwares &amp; Ingestão de Artefatos (SHA-256)
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">
            Gerenciamento completo de projetos com UUID, cadastro de múltiplos softwares e inventário técnico em área isolada.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {onOpenUpload && (
            <button
              type="button"
              onClick={onOpenUpload}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700 hover:border-[#31d6c4] hover:text-[#31d6c4] transition-colors cursor-pointer"
            >
              <Upload className="w-3.5 h-3.5 text-[#31d6c4]" />
              Upload de Projeto
            </button>
          )}

          {onOpenGitHub && (
            <button
              type="button"
              onClick={onOpenGitHub}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700 hover:border-indigo-400 hover:text-indigo-400 transition-colors cursor-pointer"
            >
              <Github className="w-3.5 h-3.5 text-indigo-400" />
              Pesquisar no GitHub
            </button>
          )}

          <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-200/70 dark:bg-[#0f141c] border border-slate-300/60 dark:border-slate-800">
            <button
              type="button"
              onClick={() => setSubTab('projects')}
              className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-colors whitespace-nowrap cursor-pointer ${
                subTab === 'projects'
                  ? 'bg-[#31d6c4] text-slate-950'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              Projetos ({projects.length})
            </button>
            <button
              type="button"
              onClick={() => setSubTab('softwares')}
              className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-colors whitespace-nowrap cursor-pointer ${
                subTab === 'softwares'
                  ? 'bg-[#31d6c4] text-slate-950'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              Softwares &amp; Inventário ({softwares.length})
            </button>
          </div>
        </div>
      </div>

      {subTab === 'projects' ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Create / Edit Project Form */}
          <form
            onSubmit={handleSaveProject}
            className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4 h-fit"
          >
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
              <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <FolderGit2 className="w-4 h-4 text-[#31d6c4]" />
                <span>{editingProject ? 'Editar Projeto' : 'Cadastrar Novo Projeto'}</span>
              </h2>
              {editingProject && (
                <button
                  type="button"
                  onClick={() => {
                    setEditingProject(null);
                    setProjName('');
                    setProjObjective('');
                    setProjDescription('');
                  }}
                  className="text-xs text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 cursor-pointer"
                >
                  Cancelar Edição
                </button>
              )}
            </div>

            <div>
              <label
                htmlFor="proj-name"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
              >
                Nome do Projeto *
              </label>
              <input
                id="proj-name"
                type="text"
                value={projName}
                onChange={(e) => setProjName(e.target.value)}
                placeholder="Ex: Comparativo de VPNs Corporativas Zero-Trust"
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#31d6c4]"
              />
            </div>

            <div>
              <label
                htmlFor="proj-domain-tags"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
              >
                Tags de Domínio Livres (Multi-Categoria MQR)
              </label>
              <input
                id="proj-domain-tags"
                type="text"
                value={projDomainTags}
                onChange={(e) => setProjDomainTags(e.target.value)}
                placeholder="Ex: cryptography, api-gateway, zero-trust, kdbx"
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#31d6c4]"
              />
            </div>

            <div>
              <label
                htmlFor="proj-qg"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
              >
                Quality Gate Transversal (SonarQube MQR)
              </label>
              <select
                id="proj-qg"
                value={projQualityGateId}
                onChange={(e) => setProjQualityGateId(e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#31d6c4]"
              >
                <option value="qg-sonar-way-mqr">Sonar way (MQR — Clean as You Code + Fudge Factor)</option>
                <option value="qg-zero-trust-strict">WinHood Zero-Trust Strict (Bloqueio CVSS &gt;= 7.0)</option>
              </select>
            </div>

            <div>
              <label
                htmlFor="proj-owner"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
              >
                Responsável Técnico *
              </label>
              <input
                id="proj-owner"
                type="text"
                value={projOwner}
                onChange={(e) => setProjOwner(e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#31d6c4]"
              />
            </div>

            <div>
              <label
                htmlFor="proj-objective"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
              >
                Objetivo Técnico da Avaliação *
              </label>
              <textarea
                id="proj-objective"
                rows={3}
                value={projObjective}
                onChange={(e) => setProjObjective(e.target.value)}
                placeholder="Descreva os critérios decisórios de segurança, arquitetura e desempenho..."
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#31d6c4]"
              />
            </div>

            <div>
              <label
                htmlFor="proj-desc"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
              >
                Descrição Detalhada
              </label>
              <textarea
                id="proj-desc"
                rows={2}
                value={projDescription}
                onChange={(e) => setProjDescription(e.target.value)}
                placeholder="Escopo, restrições normativas e observações..."
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100 focus:outline-none focus:border-[#31d6c4]"
              />
            </div>

            <button
              type="submit"
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
            >
              <Plus className="w-4 h-4" />
              {editingProject ? 'Salvar Alterações no Projeto' : 'Registrar Projeto com UUID'}
            </button>
          </form>

          {/* Projects List */}
          <div className="lg:col-span-2 space-y-4">
            {projects.length === 0 ? (
              <div className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-8 text-center">
                <p className="text-sm text-slate-500">
                  Nenhum projeto cadastrado. Utilize o formulário ao lado para criar o primeiro projeto.
                </p>
              </div>
            ) : (
              projects.map((p) => {
                const projSoftwares = softwares.filter((s) => s.projectId === p.id);
                return (
                  <div
                    key={p.id}
                    className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
                      <div>
                        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                          <span>UUID: {p.id}</span>
                          <span>·</span>
                          <span className="text-[#31d6c4] font-semibold">
                            Escopo: {p.enabledCategories?.length || 12}/12 Categorias
                          </span>
                          <span>·</span>
                          <span>Criado: {new Date(p.createdAt).toLocaleDateString('pt-BR')}</span>
                        </div>
                        <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100 mt-1">
                          {p.name}
                        </h3>
                        {(p.domainTags && p.domainTags.length > 0) && (
                          <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
                            {p.domainTags.map((tag) => (
                              <span
                                key={tag}
                                className="px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-[10px] font-mono text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700"
                              >
                                #{tag}
                              </span>
                            ))}
                          </div>
                        )}
                        <p className="text-xs text-slate-600 dark:text-slate-300 mt-1.5">
                          <strong>Objetivo:</strong> {p.objective}
                        </p>
                        {p.description && (
                          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                            {p.description}
                          </p>
                        )}
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          type="button"
                          onClick={() => {
                            setEditingProject(p);
                            setProjName(p.name);
                            setProjDomainTags((p.domainTags || [p.category || 'multi-category']).join(', '));
                            setProjQualityGateId(p.defaultQualityGateId || 'qg-sonar-way-mqr');
                            setProjObjective(p.objective);
                            setProjDescription(p.description);
                            setProjOwner(p.owner);
                          }}
                          aria-label={`Editar projeto ${p.name}`}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
                        >
                          <Edit3 className="w-3.5 h-3.5" />
                          Editar
                        </button>
                        <button
                          type="button"
                          onClick={() => setConfirmDeleteProject(p)}
                          aria-label={`Excluir projeto ${p.name}`}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border border-rose-500/40 text-rose-600 dark:text-rose-400 hover:bg-rose-500/10 cursor-pointer"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          Excluir
                        </button>
                      </div>
                    </div>

                    <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400">
                      <div>
                        <span>Responsável: {p.owner}</span>
                        <span className="mx-2">·</span>
                        <span>Softwares vinculados: {projSoftwares.length}</span>
                        <span className="mx-2">·</span>
                        <span>Eventos no histórico: {p.history.length}</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setSwProjectId(p.id);
                          setSubTab('softwares');
                        }}
                        className="text-[#31d6c4] font-semibold hover:underline cursor-pointer"
                      >
                        Gerenciar Softwares deste Projeto →
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Software Registration & Ingestion Form */}
          <form
            onSubmit={handleCreateSoftware}
            className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-3.5 h-fit"
          >
            <h2 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
              <Layers className="w-4 h-4 text-[#31d6c4]" />
              <span>Cadastrar Software &amp; Ingerir Código</span>
            </h2>

            <div>
              <label
                htmlFor="sw-project"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
              >
                Projeto Vinculado *
              </label>
              <select
                id="sw-project"
                value={swProjectId || projects[0]?.id || ''}
                onChange={(e) => setSwProjectId(e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label
                  htmlFor="sw-name"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Nome do Software *
                </label>
                <input
                  id="sw-name"
                  type="text"
                  value={swName}
                  onChange={(e) => setSwName(e.target.value)}
                  placeholder="Ex: PassGuard Enterprise"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
                />
              </div>
              <div>
                <label
                  htmlFor="sw-version"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Versão *
                </label>
                <input
                  id="sw-version"
                  type="text"
                  value={swVersion}
                  onChange={(e) => setSwVersion(e.target.value)}
                  placeholder="3.1.0"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label
                  htmlFor="sw-vendor"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Fabricante *
                </label>
                <input
                  id="sw-vendor"
                  type="text"
                  value={swVendor}
                  onChange={(e) => setSwVendor(e.target.value)}
                  placeholder="SecLabs Corp"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
                />
              </div>
              <div>
                <label
                  htmlFor="sw-source-type"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Método de Ingestão
                </label>
                <select
                  id="sw-source-type"
                  value={swSourceType}
                  onChange={(e) => setSwSourceType(e.target.value as Software['sourceType'])}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
                >
                  <option value="GIT_REPO">Repositório Git (GitHub/GitLab/Azure)</option>
                  <option value="LOCAL_AUTHORIZED">Código-Fonte Local Autorizado</option>
                  <option value="ARCHIVE">Arquivo Compactado (.zip/.tar.gz)</option>
                  <option value="COMPILED_BINARY">Aplicação Compilada</option>
                  <option value="CONTAINER">Container OCI / Docker</option>
                </select>
              </div>
            </div>

            <div>
              <label
                htmlFor="sw-domain-tags"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
              >
                Tags de Domínio do Software (separadas por vírgula)
              </label>
              <input
                id="sw-domain-tags"
                type="text"
                value={swDomainTags}
                onChange={(e) => setSwDomainTags(e.target.value)}
                placeholder="Ex: typescript, cryptography, zero-knowledge, kdbx"
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label
                  htmlFor="sw-arch"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Arquitetura
                </label>
                <input
                  id="sw-arch"
                  type="text"
                  value={swArchitecture}
                  onChange={(e) => setSwArchitecture(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
                />
              </div>
              <div>
                <label
                  htmlFor="sw-os"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Sistema Operacional
                </label>
                <input
                  id="sw-os"
                  type="text"
                  value={swOs}
                  onChange={(e) => setSwOs(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label
                  htmlFor="sw-license"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Licença
                </label>
                <input
                  id="sw-license"
                  type="text"
                  value={swLicense}
                  onChange={(e) => setSwLicense(e.target.value)}
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs text-slate-900 dark:text-slate-100"
                />
              </div>
              <div>
                <label
                  htmlFor="sw-commit"
                  className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
                >
                  Commit Hash (Opcional)
                </label>
                <input
                  id="sw-commit"
                  type="text"
                  value={swCommitHash}
                  onChange={(e) => setSwCommitHash(e.target.value)}
                  placeholder="Auto SHA-1 se vazio"
                  className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="sw-file-path"
                className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1"
              >
                Arquivo de Código-Fonte Autorizado para Ingestão Inicial
              </label>
              <input
                id="sw-file-path"
                type="text"
                value={swCustomFileName}
                onChange={(e) => setSwCustomFileName(e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-1.5 text-xs font-mono text-slate-900 dark:text-slate-100 mb-1.5"
              />
              <textarea
                rows={4}
                aria-label="Conteúdo do código-fonte para ingestão"
                value={swCustomFileContent}
                onChange={(e) => setSwCustomFileContent(e.target.value)}
                className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#080b10] px-3 py-2 text-xs font-mono text-slate-900 dark:text-slate-100"
              />
            </div>

            <button
              type="submit"
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer"
            >
              <Upload className="w-4 h-4" />
              Ingerir Artefatos e Gerar Inventário SHA-256
            </button>
          </form>

          {/* Softwares Inventory List */}
          <div className="lg:col-span-2 space-y-4">
            {softwares.map((sw) => (
              <div
                key={sw.id}
                className="rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0f141c] p-5 space-y-4"
              >
                <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
                      <span>{sw.vendor}</span>
                      <span>·</span>
                      <span>v{sw.version}</span>
                      <span>·</span>
                      <span>{sw.sourceType}</span>
                      <span>·</span>
                      <span>Licença: {sw.licenseType}</span>
                    </div>
                    <h3 className="text-lg font-bold text-slate-900 dark:text-slate-100 mt-1">
                      {sw.name}
                    </h3>
                    <p className="text-xs text-slate-600 dark:text-slate-300 mt-1">
                      {sw.description}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => setInspectedSoftware(sw)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-[#31d6c4]/15 text-[#0e9f8e] dark:text-[#31d6c4] hover:bg-[#31d6c4]/25 transition-colors cursor-pointer"
                    >
                      <FileCode2 className="w-3.5 h-3.5" />
                      Inventário &amp; Código ({sw.inventory.totalFiles} arqs)
                    </button>
                  </div>
                </div>

                {/* SHA-256 & Technical Inventory Summary */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-200 dark:border-slate-800 text-xs font-mono tabular-nums">
                  <div>
                    <div className="text-slate-400 font-sans">Arquivos Elegíveis</div>
                    <div className="font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                      {sw.inventory.eligibleFiles} / {sw.inventory.totalFiles}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-400 font-sans">Linhas de Código (LOC)</div>
                    <div className="font-bold text-slate-900 dark:text-slate-100 mt-0.5">
                      {sw.inventory.totalLinesOfCode} LOC ({sw.inventory.totalSizeBytes} B)
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-400 font-sans">Linguagens Detectadas</div>
                    <div className="font-bold text-slate-900 dark:text-slate-100 mt-0.5 truncate">
                      {sw.languages.join(', ')}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-400 font-sans">Integridade Isolada</div>
                    <div className="font-bold text-emerald-600 dark:text-[#31d6c4] mt-0.5 flex items-center gap-1">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      Verificada
                    </div>
                  </div>
                </div>

                <div className="p-2.5 rounded bg-slate-100 dark:bg-[#080b10] text-[11px] font-mono tabular-nums text-slate-600 dark:text-slate-400 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                  <div className="truncate">
                    <Hash className="w-3 h-3 inline mr-1 text-[#31d6c4]" />
                    <strong>SHA-256 Pacote:</strong> {sw.packageSha256}
                  </div>
                  <div className="shrink-0">
                    <strong>Commit:</strong> {sw.commitHash.slice(0, 12)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Modal: Confirmação de Exclusão de Projeto */}
      {confirmDeleteProject && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="del-proj-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs"
        >
          <div className="w-full max-w-md rounded-xl border border-slate-700 bg-white dark:bg-[#0f141c] p-6 space-y-4">
            <h3 id="del-proj-title" className="text-base font-bold text-slate-900 dark:text-slate-100">
              Confirmar Exclusão Permanente do Projeto
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-300 leading-relaxed">
              Tem certeza que deseja excluir o projeto{' '}
              <strong>{confirmDeleteProject.name}</strong> (UUID:{' '}
              <code className="font-mono">{confirmDeleteProject.id}</code>) e seus softwares vinculados? Esta operação será registrada no log de auditoria.
            </p>
            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setConfirmDeleteProject(null)}
                className="px-4 py-2 rounded-lg text-xs font-medium border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 cursor-pointer"
              >
                Cancelar
              </button>
              <button
                type="button"
                onClick={handleDeleteProjectConfirmed}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-rose-600 text-white hover:bg-rose-500 cursor-pointer"
              >
                Confirmar Exclusão
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Inspeção de Inventário Técnico e Código-Fonte Isolado */}
      {inspectedSoftware && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="inv-modal-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs"
        >
          <div className="w-full max-w-4xl max-h-[88vh] flex flex-col rounded-xl border border-slate-700 bg-white dark:bg-[#0f141c] overflow-hidden">
            <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
              <div>
                <h3
                  id="inv-modal-title"
                  className="text-base font-bold text-slate-900 dark:text-slate-100"
                >
                  Inventário Técnico &amp; Artefatos Isolados — {inspectedSoftware.name} (v
                  {inspectedSoftware.version})
                </h3>
                <p className="text-xs font-mono text-slate-500 dark:text-slate-400 mt-0.5">
                  Área Isolada: {inspectedSoftware.inventory.isolatedStoragePath}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setInspectedSoftware(null)}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer"
              >
                Fechar Painel
              </button>
            </div>

            <div className="p-6 overflow-y-auto df-hover-scroll space-y-6">
              {/* File Inventory Table */}
              <div>
                <h4 className="text-xs font-bold text-slate-700 dark:text-slate-300 mb-2">
                  Arquivos Ingeridos e Verificados por SHA-256 ({inspectedSoftware.inventory.files.length})
                </h4>
                <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
                  <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                    <thead>
                      <tr className="bg-slate-100 dark:bg-[#080b10] text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800">
                        <th className="py-2 px-3">Arquivo</th>
                        <th className="py-2 px-3">Linguagem</th>
                        <th className="py-2 px-3 text-right">LOC</th>
                        <th className="py-2 px-3 text-right">Tamanho</th>
                        <th className="py-2 px-3">Elegível</th>
                        <th className="py-2 px-3">SHA-256</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                      {inspectedSoftware.inventory.files.map((f) => (
                        <tr key={f.relativePath}>
                          <td className="py-2 px-3 font-semibold text-slate-900 dark:text-slate-100">
                            {f.relativePath}
                          </td>
                          <td className="py-2 px-3 font-sans text-slate-600 dark:text-slate-300">
                            {f.language}
                          </td>
                          <td className="py-2 px-3 text-right">{f.linesOfCode}</td>
                          <td className="py-2 px-3 text-right">{f.sizeBytes} B</td>
                          <td className="py-2 px-3">
                            {f.eligibleForAnalysis ? (
                              <span className="text-emerald-600 dark:text-[#31d6c4] inline-flex items-center gap-1">
                                <CheckCircle2 className="w-3 h-3" /> Sim
                              </span>
                            ) : (
                              <span className="text-slate-400">Doc/Meta</span>
                            )}
                          </td>
                          <td className="py-2 px-3 text-slate-500">{f.sha256.slice(0, 20)}...</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Add / Update Source File in Inventory */}
              <form
                onSubmit={handleIngestAdditionalFile}
                className="p-4 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#080b10] space-y-3"
              >
                <div className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2">
                  <Code className="w-4 h-4 text-[#31d6c4]" />
                  <span>Ingerir Novo Arquivo Autorizado neste Software (Sem Executar durante Ingestão)</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="sm:col-span-1">
                    <label
                      htmlFor="ingest-file-path"
                      className="block text-[11px] text-slate-500 mb-1"
                    >
                      Caminho Relativo do Arquivo
                    </label>
                    <input
                      id="ingest-file-path"
                      type="text"
                      value={ingestFileName}
                      onChange={(e) => setIngestFileName(e.target.value)}
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                  <div className="sm:col-span-2">
                    <label
                      htmlFor="ingest-file-content"
                      className="block text-[11px] text-slate-500 mb-1"
                    >
                      Conteúdo do Código-Fonte
                    </label>
                    <textarea
                      id="ingest-file-content"
                      rows={3}
                      value={ingestFileContent}
                      onChange={(e) => setIngestFileContent(e.target.value)}
                      className="w-full rounded border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#0f141c] px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                </div>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] cursor-pointer"
                >
                  Adicionar Arquivo &amp; Recalcular Hash SHA-256
                </button>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
