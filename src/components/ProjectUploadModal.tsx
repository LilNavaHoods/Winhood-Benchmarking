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
import { csrfFetch as fetch } from '../utils/csrfFetch';

async function computeClientSha256(filesMap: Record<string, string>): Promise<string> {
  const keys = Object.keys(filesMap).sort((a, b) => a.localeCompare(b));
  if (keys.length === 0) return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  const concatenated = keys.map((k) => `${k}:${filesMap[k]}`).join('\n--WINHOOD-ENTRY--\n');
  const encoder = new TextEncoder();
  const data = encoder.encode(concatenated);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
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

const IGNORED_UPLOAD_DIRS = /(^|\/)(node_modules|\.git|dist|dist-desktop|build|coverage|\.next|\.nuxt|\.cache|\.vscode|\.idea|out|target|bin|obj|vendor|__pycache__)(\/|$)/i;
const BINARY_FILE_EXTENSIONS = /\.(png|jpe?g|gif|webp|ico|bmp|tiff|pdf|exe|dll|so|dylib|bin|dat|db|sqlite|sqlite3|woff2?|ttf|eot|otf|mp3|mp4|wav|avi|mov|mkv|pyc|class|jar|war|ear|o|a|lib|pdb|vsix|dmg|iso|tar|gz|7z|rar)$/i;

function isIgnoredOrBinaryPath(relPath: string): boolean {
  const normalized = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  return IGNORED_UPLOAD_DIRS.test(normalized) || BINARY_FILE_EXTENSIONS.test(normalized);
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

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
  const [domainTagsInput, setDomainTagsInput] = useState('devsecops, mqr-strict, security, clean-code');
  const [qualityGateId, setQualityGateId] = useState('winhood-standard-v2');
  const [evaluateAll12Categories, setEvaluateAll12Categories] = useState(true);
  const [objective, setObjective] = useState('');
  const [description, setDescription] = useState('');
  const [softwareName, setSoftwareName] = useState('');
  const [softwareVendor, setSoftwareVendor] = useState('Equipe de Engenharia');
  const [softwareVersion, setSoftwareVersion] = useState('1.0.0');

  // Loaded Files Map: { relativePath: content }
  const [filesMap, setFilesMap] = useState<Record<string, string>>({});
  const [skippedCount, setSkippedCount] = useState<number>(0);
  const [packageHash, setPackageHash] = useState<string>('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    if (!isOpen) return;
    let active = true;
    computeClientSha256(filesMap)
      .then((hash) => {
        if (active) setPackageHash(hash);
      })
      .catch(() => {
        if (active) setPackageHash('');
      });
    return () => {
      active = false;
    };
  }, [filesMap, isOpen]);

  if (!isOpen) return null;

  const processFileList = async (files: FileList | File[], customRelativePaths?: Map<File, string>) => {
    const newFiles: Record<string, string> = { ...filesMap };
    let suggestedProjectName = projectName;
    let newlySkipped = 0;

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      if (!file) continue;

      const rawPath = customRelativePaths?.get(file) || (file as any).webkitRelativePath || file.name;
      const cleanPath = String(rawPath).replace(/\\/g, '/').replace(/^\/+/, '');
      if (!cleanPath) continue;

      if (!suggestedProjectName && cleanPath.includes('/')) {
        suggestedProjectName = cleanPath.split('/')[0] || '';
      }

      // 1. Handle .zip archive extraction via backend
      if (cleanPath.toLowerCase().endsWith('.zip')) {
        if (file.size > 35 * 1024 * 1024) {
          newlySkipped += 1;
          continue;
        }
        try {
          const buf = await file.arrayBuffer();
          const zipBase64 = arrayBufferToBase64(buf);
          const zipRes = await fetch('/api/projects/extract-zip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ zipBase64 }),
          });
          if (zipRes.ok) {
            const zipData = await zipRes.json();
            if (zipData.filesMap && typeof zipData.filesMap === 'object') {
              Object.assign(newFiles, zipData.filesMap);
            }
            if (typeof zipData.skippedCount === 'number') {
              newlySkipped += zipData.skippedCount;
            }
            if (!suggestedProjectName) {
              suggestedProjectName = file.name.replace(/\.zip$/i, '');
            }
          } else {
            newlySkipped += 1;
          }
        } catch {
          newlySkipped += 1;
        }
        continue;
      }

      // 2. Skip ignored directories, binary extensions, or files > 2MB
      if (isIgnoredOrBinaryPath(cleanPath) || file.size > 2 * 1024 * 1024) {
        newlySkipped += 1;
        continue;
      }

      try {
        const text = await file.text();
        if (text.includes('\0')) {
          newlySkipped += 1;
          continue;
        }
        newFiles[cleanPath] = text;
      } catch {
        newlySkipped += 1;
      }
    }

    setFilesMap(newFiles);
    if (newlySkipped > 0) {
      setSkippedCount((prev) => prev + newlySkipped);
    }
    if (!projectName && suggestedProjectName) {
      setProjectName(suggestedProjectName);
      if (!softwareName) setSoftwareName(suggestedProjectName);
    } else if (!projectName && files.length > 0 && files[0]) {
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

  const traverseFileTreeEntry = async (
    entry: any,
    parentPath: string,
    collectedFiles: File[],
    relativeMap: Map<File, string>
  ): Promise<void> => {
    if (!entry) return;
    const currentPath = parentPath ? `${parentPath}/${entry.name}` : entry.name;
    if (entry.isFile) {
      await new Promise<void>((resolve) => {
        entry.file(
          (file: File) => {
            collectedFiles.push(file);
            relativeMap.set(file, currentPath);
            resolve();
          },
          () => resolve()
        );
      });
    } else if (entry.isDirectory) {
      if (IGNORED_UPLOAD_DIRS.test(`${currentPath}/`)) {
        setSkippedCount((prev) => prev + 1);
        return;
      }
      const dirReader = entry.createReader();
      const readAllEntries = async (): Promise<any[]> => {
        const all: any[] = [];
        while (true) {
          const batch: any[] = await new Promise((resolve) => {
            dirReader.readEntries(
              (entries: any[]) => resolve(entries || []),
              () => resolve([])
            );
          });
          if (!batch || batch.length === 0) break;
          all.push(...batch);
        }
        return all;
      };
      const children = await readAllEntries();
      for (const child of children) {
        await traverseFileTreeEntry(child, currentPath, collectedFiles, relativeMap);
      }
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      const entries: any[] = [];
      for (let i = 0; i < e.dataTransfer.items.length; i++) {
        const item = e.dataTransfer.items[i];
        const entry = item && typeof (item as any).webkitGetAsEntry === 'function' ? (item as any).webkitGetAsEntry() : null;
        if (entry) entries.push(entry);
      }
      if (entries.length > 0) {
        const collectedFiles: File[] = [];
        const relativeMap = new Map<File, string>();
        for (const entry of entries) {
          await traverseFileTreeEntry(entry, '', collectedFiles, relativeMap);
        }
        if (collectedFiles.length > 0) {
          await processFileList(collectedFiles, relativeMap);
          return;
        }
      }
    }

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

    const parsedDomainTags = domainTagsInput
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean);

    setLoading(true);
    try {
      const res = await fetch('/api/projects/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: projectName.trim(),
          domainTags: parsedDomainTags.length > 0 ? parsedDomainTags : ['multi-category', 'mqr-strict'],
          defaultQualityGateId: qualityGateId,
          defaultQualityProfileIds: ['mqr-strict'],
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
        `Projeto "${data.project.name}" e software "${data.software.name} v${data.software.version}" criados com sucesso (${totalFiles} arquivos, 12 categorias habilitadas)!`,
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
                Upload &amp; Ingestão Multi-Categoria (Modo MQR (Modern Quality Regime))
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Importe código-fonte local, pastas ou arquivos .zip para avaliação transversal nas 12 categorias.
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
            <label
              htmlFor="upload-project-files-input"
              className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2"
            >
              Arquivos de Código-Fonte, Pacote .ZIP ou Diretório do Projeto
            </label>
            <div
              role="button"
              tabIndex={0}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  fileInputRef.current?.click();
                }
              }}
              className={`border-2 border-dashed rounded-xl p-6 text-center transition-all cursor-pointer ${
                isDragging
                  ? 'border-[#31d6c4] bg-[#31d6c4]/5'
                  : 'border-slate-300 dark:border-slate-700 hover:border-[#31d6c4]/60 bg-slate-50 dark:bg-[#080b10]'
              }`}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                id="upload-project-files-input"
                ref={fileInputRef}
                type="file"
                multiple
                className="hidden"
                onChange={(e) => e.target.files && processFileList(e.target.files)}
              />
              <input
                id="upload-project-folder-input"
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
                Arraste arquivos, pacotes .zip ou pastas de código aqui
              </p>
              <p className="text-[11px] text-slate-500 mb-3">
                Suporta TypeScript, JavaScript, Python, C#, Go, Java, Rust, SQL, JSON, Markdown e arquivos .ZIP (ignora automaticamente node_modules e binários).
              </p>

              <div className="flex items-center justify-center gap-2 flex-wrap">
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    fileInputRef.current?.click();
                  }}
                  className="px-3 py-1.5 rounded-lg bg-slate-200 dark:bg-slate-800 text-slate-800 dark:text-slate-200 text-xs font-medium hover:bg-slate-300 dark:hover:bg-slate-700 transition-colors cursor-pointer"
                >
                  Selecionar Arquivos / .ZIP
                </button>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    folderInputRef.current?.click();
                  }}
                  className="px-3 py-1.5 rounded-lg bg-slate-200 dark:bg-slate-800 text-slate-800 dark:text-slate-200 text-xs font-medium hover:bg-slate-300 dark:hover:bg-slate-700 transition-colors cursor-pointer"
                >
                  Selecionar Pasta
                </button>
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleManualAddFile();
                  }}
                  className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer inline-flex items-center gap-1"
                >
                  <Plus className="w-3 h-3" /> Adicionar Arquivo Manual
                </button>
              </div>
            </div>
          </div>

          {/* Files Inventory Preview */}
          {(totalFiles > 0 || skippedCount > 0) && (
            <div className="rounded-xl border border-slate-200 dark:border-slate-800 p-3 bg-slate-50 dark:bg-[#080b10] space-y-2">
              <div className="flex items-center justify-between text-xs font-semibold flex-wrap gap-2">
                <span className="text-slate-700 dark:text-slate-300">
                  {totalFiles} arquivos de código carregados ({totalLoc} LOC) • {skippedCount} arquivos ignorados automaticamente (node_modules, binários ou imagens)
                </span>
                {totalFiles > 0 && (
                  <span className="font-mono text-[10px] text-slate-500">
                    SHA-256: {packageHash.slice(0, 16)}...
                  </span>
                )}
              </div>
              {totalFiles > 0 && (
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
              )}
            </div>
          )}

          {/* Metadata Fields */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label
                htmlFor="upload-project-name"
                className="block text-[11px] font-semibold text-slate-600 dark:text-slate-400 mb-1"
              >
                Nome do Projeto *
              </label>
              <input
                id="upload-project-name"
                type="text"
                required
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                placeholder="Ex: Auditoria de Segurança API Gateway"
                className="w-full px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-[#31d6c4]"
              />
            </div>

            <div>
              <label
                htmlFor="upload-quality-gate"
                className="block text-[11px] font-semibold text-slate-600 dark:text-slate-400 mb-1"
              >
                Quality Gate Transversal (Modo MQR (Modern Quality Regime))
              </label>
              <select
                id="upload-quality-gate"
                value={qualityGateId}
                onChange={(e) => setQualityGateId(e.target.value)}
                className="w-full px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-[#31d6c4]"
              >
                <option value="winhood-standard-v2">WinHood Standard v2 (Modo MQR Oficial)</option>
                <option value="qg-sonar-way-mqr">Perfil de Qualidade Estrita (Modo MQR — Clean as You Code + Fudge Factor)</option>
                <option value="qg-zero-trust-strict">WinHood Zero-Trust Strict (Bloqueio CVSS &gt;= 7.0)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label
                htmlFor="upload-domain-tags"
                className="block text-[11px] font-semibold text-slate-600 dark:text-slate-400 mb-1"
              >
                Tags de Domínio Livres (separadas por vírgula)
              </label>
              <input
                id="upload-domain-tags"
                type="text"
                value={domainTagsInput}
                onChange={(e) => setDomainTagsInput(e.target.value)}
                placeholder="Ex: api-gateway, cryptography, microservices, kdbx"
                className="w-full px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs font-mono focus:outline-none focus:border-[#31d6c4]"
              />
            </div>
            <div className="flex items-center pt-4">
              <label className="inline-flex items-center gap-2 text-xs font-semibold text-slate-700 dark:text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={evaluateAll12Categories}
                  onChange={(e) => setEvaluateAll12Categories(e.target.checked)}
                  className="rounded accent-[#31d6c4]"
                />
                <span>Avaliar simultaneamente todas as 12 categorias (MQR)</span>
              </label>
            </div>
          </div>

          <div>
            <label
              htmlFor="upload-objective"
              className="block text-[11px] font-semibold text-slate-600 dark:text-slate-400 mb-1"
            >
              Objetivo Técnico da Avaliação *
            </label>
            <textarea
              id="upload-objective"
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
                <label
                  htmlFor="upload-software-name"
                  className="block text-[11px] font-medium text-slate-500 mb-1"
                >
                  Nome do Software
                </label>
                <input
                  id="upload-software-name"
                  type="text"
                  value={softwareName}
                  onChange={(e) => setSoftwareName(e.target.value)}
                  placeholder="Nome do software"
                  className="w-full px-2.5 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-[#31d6c4]"
                />
              </div>
              <div>
                <label
                  htmlFor="upload-software-vendor"
                  className="block text-[11px] font-medium text-slate-500 mb-1"
                >
                  Fabricante / Equipe
                </label>
                <input
                  id="upload-software-vendor"
                  type="text"
                  value={softwareVendor}
                  onChange={(e) => setSoftwareVendor(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-[#121824] text-slate-900 dark:text-slate-100 text-xs focus:outline-none focus:border-[#31d6c4]"
                />
              </div>
              <div>
                <label
                  htmlFor="upload-software-version"
                  className="block text-[11px] font-medium text-slate-500 mb-1"
                >
                  Versão Inicial
                </label>
                <input
                  id="upload-software-version"
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
