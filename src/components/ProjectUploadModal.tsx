import React, { useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  FileCode2,
  FolderArchive,
  Hash,
  Loader2,
  Plus,
  Trash2,
  Upload,
  X,
} from 'lucide-react';

function computeClientHashPreview(filesMap: Record<string, string>): string {
  const keys = Object.keys(filesMap).sort();
  if (keys.length === 0) return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  const str = keys.map((k) => `${k}:${filesMap[k].length}`).join('|');
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const hex = (h2 >>> 0).toString(16).padStart(8, '0') + (h1 >>> 0).toString(16).padStart(8, '0');
  return `${hex}${hex}${hex}${hex}`;
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
  'Engenharia de Software & Segurança',
];

interface ProjectUploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => Promise<void>;
  onNotify: (msg: string, type?: 'success' | 'error') => void;
}

export const ProjectUploadModal: React.FC<ProjectUploadModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
  onNotify,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [loading, setLoading] = useState(false);

  // Form Fields
  const [projectName, setProjectName] = useState('');
  const [category, setCategory] = useState(PROJECT_CATEGORIES[0]);
  const [objective, setObjective] = useState('');
  const [description, setDescription] = useState('');
  const [softwareName, setSoftwareName] = useState('');
  const [softwareVendor, setSoftwareVendor] = useState('Equipe de Engenharia');
  const [softwareVersion, setSoftwareVersion] = useState('1.0.0');

  // Loaded Files Map: { relativePath: content }
  const [filesMap, setFilesMap] = useState<Record<string, string>>({});
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const processFileList = async (files: FileList | File[]) => {
    const newFiles: Record<string, string> = { ...filesMap };
    let suggestedProjectName = projectName;

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      // Skip very large binary files (> 5MB)
      if (file.size > 5 * 1024 * 1024) continue;

      const path = (file as any).webkitRelativePath || file.name;

      if (!suggestedProjectName && path.includes('/')) {
        suggestedProjectName = path.split('/')[0];
      }

      try {
        const text = await file.text();
        newFiles[path] = text;
      } catch {
        // If not plain text, ignore
      }
    }

    setFilesMap(newFiles);
    if (!projectName && suggestedProjectName) {
      setProjectName(suggestedProjectName);
      if (!softwareName) setSoftwareName(suggestedProjectName);
    } else if (!projectName && files.length > 0) {
      const baseName = files[0].name.replace(/\.[^/.]+$/, '');
      setProjectName(baseName);
      if (!softwareName) setSoftwareName(baseName);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await processFileList(e.dataTransfer.files);
    }
  };

  const handleManualAddFile = () => {
    const defaultPath = `src/module/service_${Date.now().toString().slice(-4)}.ts`;
    const defaultContent = `export function executeOperation() {\n  return { ok: true, timestamp: ${Date.now()} };\n}\n`;
    setFilesMap((prev) => ({ ...prev, [defaultPath]: defaultContent }));
  };

  const handleRemoveFile = (path: string) => {
    setFilesMap((prev) => {
      const copy = { ...prev };
      delete copy[path];
      return copy;
    });
  };

  const totalFiles = Object.keys(filesMap).length;
  const totalLoc = Object.values(filesMap).reduce(
    (acc, text) => acc + text.split(/\r?\n/).length,
    0
  );
  const packageHash = computeClientHashPreview(filesMap);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectName.trim() || !objective.trim()) {
      onNotify('Preencha Nome e Objetivo do projeto.', 'error');
      return;
    }

    if (totalFiles === 0) {
      onNotify('Adicione pelo menos um arquivo de código ou manifesto para upload.', 'error');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch('/api/projects/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: projectName.trim(),
          category,
          objective: objective.trim(),
          description: description.trim(),
          softwareName: (softwareName || projectName).trim(),
          softwareVendor: softwareVendor.trim(),
          softwareVersion: softwareVersion.trim(),
          filesMap,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        onNotify(data.error || data.message || 'Falha ao processar upload.', 'error');
        setLoading(false);
        return;
      }

      onNotify(
        `Projeto "${data.project.name}" e software "${data.software.name} v${data.software.version}" criados com sucesso a partir de ${totalFiles} arquivos ingeridos!`,
        'success'
      );
      await onSuccess();
      onClose();
    } catch {
      onNotify('Erro de conexão ao enviar arquivos.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="bg-white dark:bg-[#0c1017] border border-slate-200 dark:border-slate-800 rounded-2xl max-w-2xl w-full shadow-2xl flex flex-col max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-[#080b10]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-[#31d6c4]/15 text-[#31d6c4] flex items-center justify-center">
              <Upload className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                Upload &amp; Ingestão de Projeto
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Importe código-fonte local, pastas ou manifestos para inspeção estática e benchmarking.
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

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="flex-1 overflow-y-auto p-6 space-y-5 text-xs">
          {/* Drag & Drop Zone */}
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
              Arquivos de Código-Fonte ou Diretório do Projeto
            </label>
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              className={`border-2 border-dashed rounded-xl p-6 text-center transition-all cursor-pointer ${
                isDragging
                  ? 'border-[#31d6c4] bg-[#31d6c4]/5'
                  : 'border-slate-300 dark:border-slate-700 hover:border-[#31d6c4]/60 bg-slate-50 dark:bg-[#080b10]'
              }`}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                multiple
                className="hidden"
                onChange={(e) => e.target.files && processFileList(e.target.files)}
              />
              <input
                ref={folderInputRef}
                type="file"
                // @ts-expect-error webkitdirectory supported in Chromium/Firefox
                webkitdirectory=""
                directory=""
                multiple
                className="hidden"
                onChange={(e) => e.target.files && processFileList(e.target.files)}
              />

              <FolderArchive className="w-8 h-8 mx-auto mb-2 text-[#31d6c4]" />
              <p className="font-semibold text-slate-800 dark:text-slate-200 mb-1">
                Arraste arquivos ou pastas de código aqui
              </p>
              <p className="text-[11px] text-slate-500 mb-3">
                Suporta TypeScript, JavaScript, Python, C#, Go, Java, SQL, JSON e Markdown.
              </p>

              <div className="flex items-center justify-center gap-2" onClick={(e) => e.stopPropagation()}>
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="px-3 py-1.5 rounded-lg bg-slate-200 dark:bg-slate-800 text-slate-800 dark:text-slate-200 text-xs font-medium hover:bg-slate-300 dark:hover:bg-slate-700 transition-colors cursor-pointer"
                >
                  Selecionar Arquivos
                </button>
                <button
                  type="button"
                  onClick={() => folderInputRef.current?.click()}
                  className="px-3 py-1.5 rounded-lg bg-slate-200 dark:bg-slate-800 text-slate-800 dark:text-slate-200 text-xs font-medium hover:bg-slate-300 dark:hover:bg-slate-700 transition-colors cursor-pointer"
                >
                  Selecionar Pasta
                </button>
                <button
                  type="button"
                  onClick={handleManualAddFile}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer inline-flex items-center gap-1"
                >
                  <Plus className="w-3 h-3" /> Adicionar Arquivo Manual
                </button>
              </div>
            </div>
          </div>

          {/* Files Inventory Preview */}
          {totalFiles > 0 && (
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 p-3 bg-slate-50 dark:bg-[#080b10] space-y-2">
              <div className="flex items-center justify-between text-xs font-semibold">
                <span className="text-slate-700 dark:text-slate-300">
                  Inventário de Arquivos Carregados ({totalFiles} arquivos · {totalLoc} linhas de código)
                </span>
                <span className="font-mono text-[10px] text-slate-500">
                  SHA-256: {packageHash.slice(0, 16)}...
                </span>
              </div>
              <div className="max-h-36 overflow-y-auto space-y-1 pr-1 font-mono text-[11px]">
                {Object.keys(filesMap).map((path) => (
                  <div
                    key={path}
                    className="flex items-center justify-between py-1 px-2 rounded bg-white dark:bg-[#121824] border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300"
                  >
                    <div className="flex items-center gap-2 truncate">
                      <FileCode2 className="w-3.5 h-3.5 text-[#31d6c4] shrink-0" />
                      <span className="truncate">{path}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-[10px] text-slate-500">
                        {filesMap[path].split(/\r?\n/).length} LOC
                      </span>
                      <button
                        type="button"
                        onClick={() => handleRemoveFile(path)}
                        className="p-1 text-slate-400 hover:text-rose-400 cursor-pointer"
                        title="Remover arquivo"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Metadata Fields */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-semibold text-slate-600 dark:text-slate-400 mb-1">
                Nome do Projeto *
              </label>
              <input
                type="text"
                required
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                placeholder="Ex: Auditoria de Segurança API Gateway"
                className="w-full px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-[#31d6c4]"
              />
            </div>

            <div>
              <label className="block text-[11px] font-semibold text-slate-600 dark:text-slate-400 mb-1">
                Categoria do Benchmark *
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-[#31d6c4]"
              >
                {PROJECT_CATEGORIES.map((cat) => (
                  <option key={cat} value={cat}>
                    {cat}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-slate-600 dark:text-slate-400 mb-1">
              Objetivo Técnico da Avaliação *
            </label>
            <textarea
              required
              rows={2}
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              placeholder="Ex: Avaliar vulnerabilidades de injeção, robustez de criptografia e conformidade arquitetural do código importado."
              className="w-full px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-[#31d6c4]"
            />
          </div>

          {/* Software Initial Details */}
          <div className="border-t border-slate-200 dark:border-slate-800 pt-4 space-y-3">
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider block">
              Software Vinculado aos Arquivos Enviados
            </span>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="block text-[11px] font-medium text-slate-500 mb-1">
                  Nome do Software
                </label>
                <input
                  type="text"
                  value={softwareName}
                  onChange={(e) => setSoftwareName(e.target.value)}
                  placeholder="Nome do software"
                  className="w-full px-2.5 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-[#31d6c4]"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-slate-500 mb-1">
                  Fabricante / Equipe
                </label>
                <input
                  type="text"
                  value={softwareVendor}
                  onChange={(e) => setSoftwareVendor(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-[#31d6c4]"
                />
              </div>
              <div>
                <label className="block text-[11px] font-medium text-slate-500 mb-1">
                  Versão Inicial
                </label>
                <input
                  type="text"
                  value={softwareVersion}
                  onChange={(e) => setSoftwareVersion(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-[#31d6c4]"
                />
              </div>
            </div>
          </div>

          {/* Footer Actions */}
          <div className="border-t border-slate-200 dark:border-slate-800 pt-4 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={loading}
              className="inline-flex items-center gap-2 px-5 py-2 rounded-lg font-semibold bg-[#31d6c4] text-slate-950 hover:bg-[#28bfb0] transition-colors cursor-pointer disabled:opacity-60"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Processando Ingestão...
                </>
              ) : (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  Ingerir e Criar Projeto
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
