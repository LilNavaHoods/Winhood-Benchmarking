import path from 'node:path';
import type { CodeExecutionFlowStep } from '../types/benchmark';
import type { AstCallSite, AstFunctionNode, AstIssueCandidate, AstParseResult } from './types';

export type TaintSinkType =
  | 'SQL_INJECTION'
  | 'COMMAND_INJECTION'
  | 'CODE_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'XSS'
  | 'SSRF'
  | 'NOSQL_INJECTION'
  | 'LDAP_INJECTION'
  | 'XPATH_INJECTION'
  | 'XXE'
  | 'INSECURE_DESERIALIZATION'
  | 'OPEN_REDIRECT'
  | 'SSTI'
  | 'PROTOTYPE_POLLUTION'
  | 'LOG_INJECTION';

export interface TaintAnalysisOptions {
  /** Maximum interprocedural call depth (default: 6, replaces old hardcoded 2-hop limit). */
  maxCallDepth?: number;
  /** Maximum graph nodes visited per traversal (resource & cycle guard, default: 500). */
  maxVisitedNodes?: number;
  /** Maximum total analysis budget in milliseconds (default: 2000ms). */
  maxTimeMs?: number;
}

export interface TaintCallGraphNode {
  id: string;
  filePath: string;
  functionName: string;
  params: string[];
  isExported: boolean;
  startLine: number;
  endLine: number;
  returnsTaintedParamIndices: number[];
}

export interface TaintCallGraphEdge {
  fromNodeId: string;
  toNodeId: string;
  callLine: number;
  calleeText: string;
  argIndicesPropagated: number[];
  isCrossFile: boolean;
}

export interface TaintIncompletePath {
  reason: 'DYNAMIC_CALL_DISPATCH' | 'MAX_DEPTH_REACHED' | 'CYCLE_DETECTED' | 'RESOURCE_BUDGET_EXCEEDED';
  filePath: string;
  lineNumber: number;
  functionName: string;
  calleeText: string;
  confidenceImpact: 'INCONCLUSIVE' | 'LOW';
  explanation: string;
}

export interface TaintCallGraph {
  nodes: TaintCallGraphNode[];
  edges: TaintCallGraphEdge[];
  dynamicCallSites: number;
  cyclesDetected: number;
  truncatedPaths: number;
}

export interface TaintAnalysisDiagnosticsResult {
  issues: AstIssueCandidate[];
  callGraph: TaintCallGraph;
  incompletePaths: TaintIncompletePath[];
  stats: {
    maxDepthConfigured: number;
    maxDepthObserved: number;
    nodesCount: number;
    edgesCount: number;
    cyclesDetected: number;
    truncatedPaths: number;
    dynamicCallSites: number;
    elapsedMs: number;
  };
}

interface TaintedVarState {
  originFile: string;
  originLine: number;
  originFunction: string;
  originSymbol: string;
  originSnippet: string;
  sanitizedFor: Set<TaintSinkType>;
  steps: CodeExecutionFlowStep[];
}

const SOURCE_PARAM_HINT =
  /(input|query|filter|path|target|cmd|command|url|uri|webhook|endpoint|req|request|body|param|user|title|name|payload|raw|sql|expr|file|html|tpl|data|id|arg|value)/i;

const DYNAMIC_DISPATCH_PATTERN =
  /\[[^\]]+\]|\.(?:apply|call|bind)$|^(?:Reflect\.apply|window\[|globalThis\[|handlers\[)/;

export const SINK_RULES: Array<{
  calleePattern: RegExp;
  ruleId: string;
  title: string;
  cwe: string;
  sinkType: TaintSinkType;
  remediation: string;
}> = [
  {
    calleePattern:
      /^(?:execSync|exec|execFile|execFileSync|system|popen|Popen|check_output)$|^(?:os|subprocess|exec|child_process|Runtime\.getRuntime\(\))\.(?:system|popen|run|Popen|call|check_output|exec|execSync|execFile|Command|CommandContext)$/,
    ruleId: 'taint:S2076',
    title: 'Fluxo Taint interprocedural até execução de comando OS (CWE-78)',
    cwe: 'CWE-78',
    sinkType: 'COMMAND_INJECTION',
    remediation: 'Substituir por execFile/spawn com shell: false e allowlist de argumentos.',
  },
  {
    calleePattern: /^(eval|Function|execfile|compile|runInNewContext|runInThisContext)$/i,
    ruleId: 'taint:S1523',
    title: 'Fluxo Taint até avaliação dinâmica de código (CWE-95)',
    cwe: 'CWE-95',
    sinkType: 'CODE_INJECTION',
    remediation: 'Eliminar eval/new Function e validar entrada contra esquema estrito.',
  },
  {
    calleePattern:
      /^(?:query|execute|executemany|raw|executeQuery|executeUpdate|createNativeQuery|ExecuteReader|queryVaultEntriesRaw|Query|QueryRow|QueryContext|Exec|ExecContext)$/i,
    ruleId: 'taint:S3649',
    title: 'Fluxo Taint até sink de consulta SQL (CWE-89)',
    cwe: 'CWE-89',
    sinkType: 'SQL_INJECTION',
    remediation: 'Utilizar Prepared Statements parametrizados (? / $1) em vez de concatenação.',
  },
  {
    calleePattern:
      /^(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|open|Open|ReadFile|WriteFile|FileInputStream)$|^Files\.(?:readString|readAllBytes|write)$/i,
    ruleId: 'taint:S2083',
    title: 'Fluxo Taint até operação de sistema de arquivos (Path Traversal CWE-22)',
    cwe: 'CWE-22',
    sinkType: 'PATH_TRAVERSAL',
    remediation: 'Normalizar com path.basename/path.resolve e validar fronteira de diretório raiz permitido.',
  },
  {
    calleePattern:
      /^(?:renderHtml|sendHtml|writeHtml|dangerouslySetInnerHTML|render_template_string|Markup)$/i,
    ruleId: 'taint:S5131',
    title: 'Fluxo Taint até renderização HTML não escapada (XSS CWE-79)',
    cwe: 'CWE-79',
    sinkType: 'XSS',
    remediation: 'Aplicar escape HTML contextual (escapeHtml/DOMPurify) antes de renderizar conteúdo.',
  },
  {
    calleePattern:
      /^(?:fetch|urlopen|httpGet)$|^(?:axios|requests|http|https|urllib\.request|httpClient|WebClient|RestTemplate)\.(?:get|post|put|delete|request|Get|Post|Do|urlopen|send|exchange|getForObject)$/i,
    ruleId: 'taint:S5144',
    title: 'Fluxo Taint interprocedural até requisição de saída SSRF (CWE-918)',
    cwe: 'CWE-918',
    sinkType: 'SSRF',
    remediation: 'Validar URLs via SsrfGuard/allowlist de domínios bloqueando loopback, link-local e faixas privadas RFC1918.',
  },
  {
    calleePattern: /^(?:\$where|findByRawQuery|aggregateRaw)$|^(?:collection|db)\.(?:find|findOne|updateMany|deleteMany)$/i,
    ruleId: 'taint:S5147',
    title: 'Fluxo Taint até consulta NoSQL sem tipagem estrita (NoSQL Injection CWE-943)',
    cwe: 'CWE-943',
    sinkType: 'NOSQL_INJECTION',
    remediation: 'Converter parâmetros para string/primitivo escalar e proibir operadores $where/$ne/$gt vindos do cliente.',
  },
  {
    calleePattern: /^(?:ldapSearch|searchLdap)$|^(?:ldapClient|dirContext)\.(?:search|bind)$/i,
    ruleId: 'taint:S2078',
    title: 'Fluxo Taint até filtro de diretório LDAP (LDAP Injection CWE-90)',
    cwe: 'CWE-90',
    sinkType: 'LDAP_INJECTION',
    remediation: 'Escapar caracteres especiais RFC 4515 (*, (, ), \\, NUL) antes de montar filtros LDAP.',
  },
  {
    calleePattern: /^(?:xpathEvaluate|selectNodes|selectSingleNode)$|^xpath\.(?:select|evaluate)$/i,
    ruleId: 'taint:S2091',
    title: 'Fluxo Taint até expressão XPath (XPath Injection CWE-643)',
    cwe: 'CWE-643',
    sinkType: 'XPATH_INJECTION',
    remediation: 'Utilizar XPath parametrizado (XPathVariableResolver) em vez de interpolação.',
  },
  {
    calleePattern: /^(?:parseXml|parseXmlString|fromstring|SAXParser)$|^etree\.(?:fromstring|parse)$/i,
    ruleId: 'taint:S2755',
    title: 'Fluxo Taint até parser XML susceptível a Entidades Externas (XXE CWE-611)',
    cwe: 'CWE-611',
    sinkType: 'XXE',
    remediation: 'Desabilitar DTDs externos e resolve_entities no parser XML.',
  },
  {
    calleePattern: /^(?:unserialize|deserialize|loads|yamlLoad)$|^(?:pickle|marshal|yaml|ObjectInputStream)\.(?:loads|load|readObject)$/i,
    ruleId: 'taint:S5135',
    title: 'Fluxo Taint até desserialização insegura de objetos (CWE-502)',
    cwe: 'CWE-502',
    sinkType: 'INSECURE_DESERIALIZATION',
    remediation: 'Substituir por JSON.parse com validação de schema ou yaml.safe_load.',
  },
  {
    calleePattern: /^(?:redirect|sendRedirect)$|^res\.redirect$/i,
    ruleId: 'taint:S5146',
    title: 'Fluxo Taint até redirecionamento HTTP aberto (Open Redirect CWE-601)',
    cwe: 'CWE-601',
    sinkType: 'OPEN_REDIRECT',
    remediation: 'Validar o destino de redirecionamento contra uma lista estrita de caminhos relativos internos.',
  },
  {
    calleePattern: /^(?:compileTemplate|renderTemplateString|ejsRender|pugRender|handlebarsCompile)$/i,
    ruleId: 'taint:S5334',
    title: 'Fluxo Taint até compilação de template no servidor (SSTI CWE-1336)',
    cwe: 'CWE-1336',
    sinkType: 'SSTI',
    remediation: 'Passar dados de usuário apenas como contexto de variáveis para templates estáticos pré-compilados.',
  },
  {
    calleePattern: /^(?:deepMerge|mergeObjects|assignDeep|defaultsDeep)$/i,
    ruleId: 'taint:S5148',
    title: 'Fluxo Taint até fusão recursiva de objetos (Prototype Pollution CWE-1321)',
    cwe: 'CWE-1321',
    sinkType: 'PROTOTYPE_POLLUTION',
    remediation: 'Bloquear chaves __proto__, constructor e prototype e usar Object.create(null).',
  },
  {
    calleePattern: /^(?:auditLogRaw|writeRawLog)$/i,
    ruleId: 'taint:S5145',
    title: 'Fluxo Taint até gravação de log sem neutralização de CRLF (Log Injection CWE-117)',
    cwe: 'CWE-117',
    sinkType: 'LOG_INJECTION',
    remediation: 'Remover quebras de linha (\\r, \\n) e caracteres de controle antes de registrar entradas externas.',
  },
];

function isRegexPrototypeExec(callee: string, calleeBase?: string): boolean {
  if (calleeBase !== 'exec' && !callee.endsWith('.exec')) return false;
  // child_process.exec / cp.exec / proc.exec / bare exec() are OS command sinks;
  // regex.exec / re.exec / /.../.exec are JavaScript RegExp.prototype.exec
  if (callee === 'exec') return false;
  if (/^(?:child_process|cp|proc|nodeChildProcess)\.exec$/i.test(callee)) return false;
  return callee.endsWith('.exec');
}

function matchesSinkRule(
  rule: (typeof SINK_RULES)[number],
  callee: string,
  calleeBase?: string
): boolean {
  if (isRegexPrototypeExec(callee, calleeBase)) {
    return false;
  }
  if (rule.calleePattern.test(callee)) return true;
  if (calleeBase && rule.calleePattern.test(calleeBase)) return true;
  return false;
}

const ALL_TAINT_SINKS: TaintSinkType[] = [
  'SQL_INJECTION',
  'COMMAND_INJECTION',
  'CODE_INJECTION',
  'PATH_TRAVERSAL',
  'XSS',
  'SSRF',
  'NOSQL_INJECTION',
  'LDAP_INJECTION',
  'XPATH_INJECTION',
  'XXE',
  'INSECURE_DESERIALIZATION',
  'OPEN_REDIRECT',
  'SSTI',
  'PROTOTYPE_POLLUTION',
  'LOG_INJECTION',
];

function getSanitizedSinksForContext(
  ctx: NonNullable<AstFunctionNode['variableBindings'][number]['sanitizerContext']> | undefined
): TaintSinkType[] {
  switch (ctx) {
    case 'NUMERIC':
      return ALL_TAINT_SINKS;
    case 'SQL_PREPARED':
      return ['SQL_INJECTION', 'NOSQL_INJECTION'];
    case 'HTML_ESCAPE':
      return ['XSS', 'SSTI', 'LOG_INJECTION'];
    case 'PATH_BASENAME':
      return ['PATH_TRAVERSAL'];
    case 'URL_ENCODE':
      // encodeURIComponent ONLY encodes URL query components; it MUST NOT clear SQL/CMD/CODE/PATH/SSRF taint!
      return ['OPEN_REDIRECT', 'LOG_INJECTION'];
    case 'CRYPTO_KDF':
      return ['SQL_INJECTION', 'XSS', 'NOSQL_INJECTION'];
    case 'GENERIC_SCHEMA':
      return ALL_TAINT_SINKS;
    default:
      return [];
  }
}

function makeNodeId(fn: AstFunctionNode): string {
  return `${fn.filePath}:${fn.name}:${fn.startLine}`;
}

function resolveImportCandidates(
  fromFile: string,
  importPath: string,
  availableFiles: Set<string>
): string[] {
  if (!importPath.startsWith('.')) return [];
  const baseDir = path.posix.dirname(fromFile.replace(/\\/g, '/'));
  const resolvedBase = path.posix.normalize(path.posix.join(baseDir, importPath));
  const exts = ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.py', '/index.ts', '/index.js'];
  const matches: string[] = [];
  for (const ext of exts) {
    const candidate = `${resolvedBase}${ext}`;
    if (availableFiles.has(candidate)) {
      matches.push(candidate);
    }
  }
  return matches;
}

/**
 * TaintAnalyzer (Call-Graph + Multi-Hop Data-Flow Engine)
 *
 * Replaces the previous 2-hop depth cap with a structured Call-Graph + bounded interprocedural
 * data-flow engine:
 * - Configurable maxCallDepth (default 6), maxVisitedNodes (default 500), and maxTimeMs (default 2000).
 * - Import-aware cross-file function resolution with deterministic ordering.
 * - Intermediate sanitizer propagation (tracks sanitizers applied inside callee functions as well as callers).
 * - Cycle detection for mutual/direct recursion without infinite loops.
 * - Explicit tracking of dynamic/indirect dispatch and truncated paths (emits INCONCLUSIVE / LOW diagnostics).
 * - Context-sensitive sanitization: encodeURIComponent never neutralizes SQLi/Command Injection/SSRF.
 */
export class TaintAnalyzer {
  public static analyzeFlows(
    parseResults: AstParseResult[],
    filesMap: Record<string, string>,
    options?: TaintAnalysisOptions
  ): AstIssueCandidate[] {
    return TaintAnalyzer.analyzeFlowsWithDiagnostics(parseResults, filesMap, options).issues;
  }

  public static analyzeFlowsWithDiagnostics(
    parseResults: AstParseResult[],
    filesMap: Record<string, string>,
    options?: TaintAnalysisOptions
  ): TaintAnalysisDiagnosticsResult {
    const startedMs = performance.now();
    const maxCallDepth = Math.max(1, Math.min(20, options?.maxCallDepth ?? 6));
    const maxVisitedNodes = Math.max(20, Math.min(5000, options?.maxVisitedNodes ?? 500));
    const maxTimeMs = Math.max(100, Math.min(30_000, options?.maxTimeMs ?? 2000));

    const taintIssues: AstIssueCandidate[] = [];
    const incompletePaths: TaintIncompletePath[] = [];
    const fnByName = new Map<string, AstFunctionNode[]>();
    const fnByFileAndName = new Map<string, AstFunctionNode[]>();
    const astIssuesByFile = new Map<string, AstIssueCandidate[]>();
    const importsByFile = new Map<string, Map<string, string[]>>();
    const availableFiles = new Set<string>(parseResults.map((p) => p.filePath.replace(/\\/g, '/')));

    const sortedParseResults = [...parseResults].sort((a, b) => a.filePath.localeCompare(b.filePath));
    for (const parsed of sortedParseResults) {
      astIssuesByFile.set(parsed.filePath, parsed.issues);
      const sortedFns = [...parsed.functions].sort(
        (a, b) => a.startLine - b.startLine || a.name.localeCompare(b.name)
      );
      for (const fn of sortedFns) {
        const list = fnByName.get(fn.name) || [];
        list.push(fn);
        fnByName.set(fn.name, list);

        const fKey = `${fn.filePath.replace(/\\/g, '/')}::${fn.name}`;
        const flist = fnByFileAndName.get(fKey) || [];
        flist.push(fn);
        fnByFileAndName.set(fKey, flist);
      }

      const symbolToTargetFiles = new Map<string, string[]>();
      for (const imp of parsed.imports || []) {
        const resolvedFiles = resolveImportCandidates(parsed.filePath, imp.sourcePath, availableFiles);
        if (resolvedFiles.length === 0) continue;
        for (const sym of imp.importedSymbols || []) {
          const prev = symbolToTargetFiles.get(sym.name) || [];
          symbolToTargetFiles.set(sym.name, Array.from(new Set([...prev, ...resolvedFiles])));
        }
      }
      importsByFile.set(parsed.filePath, symbolToTargetFiles);
    }

    const getLineSnippet = (filePath: string, lineNo: number): string => {
      const content = filesMap[filePath] || '';
      const lines = content.split(/\r?\n/);
      return (lines[lineNo - 1] || '').trim();
    };

    const functionHasSafeSqlHandling = (fn: AstFunctionNode, fileContent: string): boolean => {
      const lines = fileContent.split(/\r?\n/).slice(Math.max(0, fn.startLine - 1), fn.endLine);
      const body = lines.join('\n');
      const usesParamPlaceholder =
        (body.includes('VALUES (?') ||
          body.includes('= ?') ||
          body.includes('= %s') ||
          /\$\d+/.test(body)) &&
        !body.includes('+') &&
        !body.includes('f"') &&
        !body.includes("f'");
      return usesParamPlaceholder && !body.includes('${');
    };

    const functionHasSafeSsrfGuard = (fn: AstFunctionNode, fileContent: string, call?: AstCallSite): boolean => {
      const lines = fileContent.split(/\r?\n/).slice(Math.max(0, fn.startLine - 1), fn.endLine);
      const body = lines.join('\n');
      if (/SsrfGuard|validateUrl|assertSafeExternalUrl|isAllowedHost/i.test(body)) {
        return true;
      }
      const isFrontendComponent = /\.(?:tsx|jsx)$/i.test(fn.filePath);
      const snippet = call?.snippet || '';
      const firstArg = (call?.argsText?.[0] || '').trim();
      // Browser React components calling relative /api/... endpoints or internal workerUrl base paths are not SSRF
      if (isFrontendComponent && /^(?:['"`]\/|['"`]\.\.?\/)/.test(firstArg)) {
        return true;
      }
      if (/^(?:['"`]\/api\/|`\$\{this\.workerUrl\}\/)/.test(firstArg)) {
        return true;
      }
      if (isFrontendComponent && /fetch\s*\(\s*['"`]\/api\//.test(snippet)) {
        return true;
      }
      if (/fetch\s*\(\s*`\$\{this\.workerUrl\}\//.test(snippet)) {
        return true;
      }
      return false;
    };

    const functionHasSafeCommandGuard = (fn: AstFunctionNode, fileContent: string, call?: AstCallSite): boolean => {
      const callee = call?.callee || '';
      const calleeBase = call?.calleeBase || '';
      if (calleeBase === 'execFileSync' || calleeBase === 'execFile' || callee.endsWith('.execFileSync') || callee.endsWith('.execFile')) {
        const lines = fileContent.split(/\r?\n/).slice(Math.max(0, fn.startLine - 1), fn.endLine);
        const body = lines.join('\n');
        // execFile/execFileSync with explicit shell: false and argument array (no shell: true)
        if (/shell\s*:\s*false/.test(body) && !/shell\s*:\s*true/.test(body)) {
          return true;
        }
      }
      return false;
    };

    const functionHasSafePathConfinement = (fn: AstFunctionNode, fileContent: string, call?: AstCallSite): boolean => {
      const lines = fileContent.split(/\r?\n/).slice(Math.max(0, fn.startLine - 1), fn.endLine);
      const body = lines.join('\n');
      const firstArg = (call?.argsText?.[0] || '').trim();
      // Numeric file descriptor opened via fs.openSync (e.g., fd, hfd, sfd) is not a user path string
      if (/^(?:fd|hfd|sfd|fileFd|tmpFd)$/.test(firstArg) && /fs\.openSync\s*\(/.test(body)) {
        return true;
      }
      // Explicit path confinement / traversal guard in function or surrounding module
      if (
        /assertPathInside|assertSafe(?:Child|File|Relative|Artifact|Workspace)?Path|resolveSafe(?:Child|File)?Path|isPathInside|ensureInside|path\.basename\s*\(|startsWith\s*\([^)]*path\.sep|startsWith\s*\([^)]*`\$\{[^}]+\}\//i.test(
          body
        ) ||
        /assertPathInside|assertSafe(?:Child|File|Relative|Artifact|Workspace)?Path|resolveSafe(?:Child|File)?Path|isPathInside/i.test(
          fileContent
        )
      ) {
        return true;
      }
      // Internal instance-owned path properties (this.storePath, this.jobsFilePath, atomic tmp/checksum siblings)
      if (
        /^this\./.test(firstArg) ||
        /\b(?:tmp|tmpFile|tmpPath|tmpSha|backupPath|seqPath|hashPath|checksumPath|trustStorePath|kekFilePath|storePath|propsFilePath|reportTaskPath|sarifPath|histPath|metaPath|metaAbsPath|manifestAbsPath|configPath|cachePath|lockPath)\b/.test(
          firstArg
        )
      ) {
        if (
          /this\.\w*(?:Path|Dir|File|Root|Store|Base)|path\.join\s*\(|path\.resolve\s*\(|resolve(?:Key|Trust|Store|Backup|Database|Snapshot|History|WinHood)/i.test(
            body
          ) ||
          /(?:KeyManagementService|PersistentDatabaseManager|ReferenceRegistry|ProjectBackupService|SonarScannerExecutor|EncryptedArtifactStore)/.test(
            fileContent
          )
        ) {
          return true;
        }
      }
      // Directory traversal walk over fs.readdirSync entries starting from an already-validated internal root
      if (/fs\.readdirSync|readdirSync/.test(body) && /entry\.name|dirent\.name/.test(body)) {
        return true;
      }
      // Internal storage/tooling modules operating strictly on internal resolved directories (never HTTP req.* input)
      if (
        !/\breq\.(?:body|query|params|headers)\b/.test(body) &&
        /(?:process\.env\.WINHOOD_|os\.tmpdir|WINHOOD_DATA_DIR|this\.(?:baseDir|dataDir|storePath|backupRootDir|registryDir))/.test(
          fileContent
        ) &&
        /(?:path\.resolve|path\.join|this\.\w*(?:Dir|Path|Store|Root)|\.sha256|\.tmp|\.bak|\.seq|metadata\.json|manifest\.json|history\.json)/.test(
          body
        )
      ) {
        return true;
      }
      return false;
    };

    // Compute per-function return taint summaries (which parameter indices propagate to return value)
    const fnReturnsTaint = new Map<string, boolean>();
    const fnReturnTaintedParamIndices = new Map<string, number[]>();
    const graphNodes: TaintCallGraphNode[] = [];
    const graphEdges: TaintCallGraphEdge[] = [];
    const edgeDedup = new Set<string>();

    for (const parsed of sortedParseResults) {
      for (const fn of parsed.functions) {
        const nodeId = makeNodeId(fn);
        const paramSet = new Set(fn.params);
        const taintedLocal = new Map<string, Set<number>>();
        fn.params.forEach((p, idx) => taintedLocal.set(p, new Set([idx])));

        for (const b of fn.variableBindings) {
          if (b.isSanitized && getSanitizedSinksForContext(b.sanitizerContext).length >= 3) {
            taintedLocal.delete(b.varName);
          } else {
            const combined = new Set<number>();
            for (const dep of b.dependencies) {
              const depIndices = taintedLocal.get(dep);
              if (depIndices) {
                for (const i of depIndices) combined.add(i);
              } else if (paramSet.has(dep)) {
                combined.add(fn.params.indexOf(dep));
              }
            }
            if (combined.size > 0) {
              taintedLocal.set(b.varName, combined);
            }
          }
        }

        const returnedIndices = new Set<number>();
        for (const rv of fn.returnValues) {
          const idxs = taintedLocal.get(rv);
          if (idxs) {
            for (const i of idxs) returnedIndices.add(i);
          }
        }
        const sortedIndices = Array.from(returnedIndices).sort((a, b) => a - b);
        fnReturnTaintedParamIndices.set(nodeId, sortedIndices);
        if (sortedIndices.length > 0) {
          fnReturnsTaint.set(fn.name, true);
        }

        graphNodes.push({
          id: nodeId,
          filePath: fn.filePath,
          functionName: fn.name,
          params: [...fn.params],
          isExported: fn.isExported,
          startLine: fn.startLine,
          endLine: fn.endLine,
          returnsTaintedParamIndices: sortedIndices,
        });
      }
    }

    const resolveTargetFunctions = (caller: AstFunctionNode, call: AstCallSite): AstFunctionNode[] => {
      const calleeName = call.calleeBase || call.callee;
      const fileImports = importsByFile.get(caller.filePath);
      const importedFiles = fileImports?.get(calleeName);
      const prioritized: AstFunctionNode[] = [];
      const seenIds = new Set<string>();

      // 1. Prefer explicitly imported target files
      if (importedFiles && importedFiles.length > 0) {
        for (const tf of importedFiles) {
          const matches = fnByFileAndName.get(`${tf}::${calleeName}`) || [];
          for (const m of matches) {
            const id = makeNodeId(m);
            if (!seenIds.has(id)) {
              seenIds.add(id);
              prioritized.push(m);
            }
          }
        }
      }
      // 2. Same-file helper functions
      const localMatches = fnByFileAndName.get(`${caller.filePath.replace(/\\/g, '/')}::${calleeName}`) || [];
      for (const m of localMatches) {
        const id = makeNodeId(m);
        if (!seenIds.has(id)) {
          seenIds.add(id);
          prioritized.push(m);
        }
      }
      // 3. Global name match fallback (for languages/patterns without explicit import edges)
      if (prioritized.length === 0) {
        for (const m of fnByName.get(calleeName) || []) {
          const id = makeNodeId(m);
          if (!seenIds.has(id)) {
            seenIds.add(id);
            prioritized.push(m);
          }
        }
      }
      return prioritized;
    };

    // Build explicit Call-Graph edges
    let dynamicCallSites = 0;
    for (const parsed of sortedParseResults) {
      for (const fn of parsed.functions) {
        const fromId = makeNodeId(fn);
        for (const call of fn.callsMade) {
          if (DYNAMIC_DISPATCH_PATTERN.test(call.callee)) {
            dynamicCallSites += 1;
            continue;
          }
          const targets = resolveTargetFunctions(fn, call);
          for (const target of targets) {
            const toId = makeNodeId(target);
            const eKey = `${fromId}->${toId}@${call.lineNumber}`;
            if (edgeDedup.has(eKey)) continue;
            edgeDedup.add(eKey);
            const argIndices: number[] = [];
            call.argsText.forEach((argTxt, idx) => {
              if (fn.params.some((p) => argTxt.includes(p)) || call.argIdentifiers.length > 0) {
                argIndices.push(idx);
              }
            });
            graphEdges.push({
              fromNodeId: fromId,
              toNodeId: toId,
              callLine: call.lineNumber,
              calleeText: call.callee,
              argIndicesPropagated: argIndices,
              isCrossFile: fn.filePath !== target.filePath,
            });
          }
        }
      }
    }

    const dedup = new Set<string>();
    const incompleteDedup = new Set<string>();
    let cyclesDetected = 0;
    let truncatedPaths = 0;
    let maxDepthObserved = 0;

    const recordIncompletePath = (entry: TaintIncompletePath): void => {
      const key = `${entry.reason}|${entry.filePath}|${entry.lineNumber}|${entry.calleeText}`;
      if (incompleteDedup.has(key)) return;
      incompleteDedup.add(key);
      incompletePaths.push(entry);
    };

    /**
     * Computes which sinks are neutralized inside `fn` for incoming parameter(s) before passing downstream.
     */
    const computeSanitizersAppliedInFunction = (fn: AstFunctionNode): Set<TaintSinkType> => {
      const neutralized = new Set<TaintSinkType>();
      for (const b of fn.variableBindings) {
        if (b.isSanitized) {
          for (const sink of getSanitizedSinksForContext(b.sanitizerContext)) {
            neutralized.add(sink);
          }
        }
      }
      return neutralized;
    };

    interface DeepSinkResolution {
      targetFn: AstFunctionNode;
      sinkLine: number;
      sinkSnippet: string;
      sinkCwe: string;
      sinkType: TaintSinkType;
      sinkCallee: string;
      hopDepth: number;
      sanitizersEncountered: Set<TaintSinkType>;
      hopChain: Array<{ caller: AstFunctionNode; callLine: number; calleeText: string; snippet: string }>;
    }

    const resolveDeepSink = (
      fn: AstFunctionNode,
      depth: number,
      activeStack: Set<string>,
      sanitizedSoFar: Set<TaintSinkType>,
      budget: { visited: number }
    ): DeepSinkResolution | null => {
      if (depth > maxDepthObserved) maxDepthObserved = depth;

      if (performance.now() - startedMs > maxTimeMs) {
        truncatedPaths += 1;
        recordIncompletePath({
          reason: 'RESOURCE_BUDGET_EXCEEDED',
          filePath: fn.filePath,
          lineNumber: fn.startLine,
          functionName: fn.name,
          calleeText: fn.name,
          confidenceImpact: 'INCONCLUSIVE',
          explanation: `Orçamento de tempo (${maxTimeMs}ms) atingido durante rastreamento interprocedural em "${fn.name}".`,
        });
        return null;
      }

      if (budget.visited >= maxVisitedNodes) {
        truncatedPaths += 1;
        recordIncompletePath({
          reason: 'RESOURCE_BUDGET_EXCEEDED',
          filePath: fn.filePath,
          lineNumber: fn.startLine,
          functionName: fn.name,
          calleeText: fn.name,
          confidenceImpact: 'INCONCLUSIVE',
          explanation: `Limite de nós visitados (${maxVisitedNodes}) atingido ao rastrear "${fn.name}".`,
        });
        return null;
      }
      budget.visited += 1;

      const nodeId = makeNodeId(fn);
      if (activeStack.has(nodeId)) {
        cyclesDetected += 1;
        recordIncompletePath({
          reason: 'CYCLE_DETECTED',
          filePath: fn.filePath,
          lineNumber: fn.startLine,
          functionName: fn.name,
          calleeText: fn.name,
          confidenceImpact: 'LOW',
          explanation: `Ciclo recursivo detectado no grafo de chamadas ao revisitar "${fn.name}" (${fn.filePath}:${fn.startLine}); recursão encerrada com segurança.`,
        });
        return null;
      }

      if (depth > maxCallDepth) {
        truncatedPaths += 1;
        recordIncompletePath({
          reason: 'MAX_DEPTH_REACHED',
          filePath: fn.filePath,
          lineNumber: fn.startLine,
          functionName: fn.name,
          calleeText: fn.name,
          confidenceImpact: 'INCONCLUSIVE',
          explanation: `Profundidade máxima configurada (${maxCallDepth} saltos) atingida em "${fn.name}". Fluxo truncado como INCONCLUSIVE.`,
        });
        return null;
      }

      const nextStack = new Set(activeStack);
      nextStack.add(nodeId);

      const fileContent = filesMap[fn.filePath] || '';
      const safeSql = functionHasSafeSqlHandling(fn, fileContent);
      const safeSsrf = functionHasSafeSsrfGuard(fn, fileContent);

      // Accumulate sanitizers applied to variables inside this intermediate function
      const combinedSanitized = new Set<TaintSinkType>(sanitizedSoFar);
      const localSanitizers = computeSanitizersAppliedInFunction(fn);
      // Only treat local sanitizer as neutralizing if variables actually bind params through it
      const paramSet = new Set(fn.params);
      const sanitizedVarNames = new Set<string>();
      for (const b of fn.variableBindings) {
        if (b.isSanitized && b.dependencies.some((d) => paramSet.has(d) || sanitizedVarNames.has(d))) {
          sanitizedVarNames.add(b.varName);
          for (const s of getSanitizedSinksForContext(b.sanitizerContext)) {
            combinedSanitized.add(s);
          }
        }
      }

      // 1. Direct sink call inside `fn`
      for (const c of fn.callsMade) {
        const rule = SINK_RULES.find((r) => matchesSinkRule(r, c.callee, c.calleeBase));
        if (!rule) continue;
        if (rule.sinkType === 'SQL_INJECTION' && safeSql) continue;
        if (rule.sinkType === 'SSRF' && (safeSsrf || functionHasSafeSsrfGuard(fn, fileContent, c))) continue;
        if (rule.sinkType === 'COMMAND_INJECTION' && functionHasSafeCommandGuard(fn, fileContent, c)) continue;
        if (rule.sinkType === 'PATH_TRAVERSAL' && functionHasSafePathConfinement(fn, fileContent, c)) continue;
        if (combinedSanitized.has(rule.sinkType)) continue;
        // Ensure a parameter or variable derived from parameters flows to the sink (if params exist)
        const sinkUsesLocalOrParam =
          fn.params.length === 0 ||
          c.argIdentifiers.some(
            (id) =>
              paramSet.has(id) ||
              fn.variableBindings.some((vb) => vb.varName === id)
          );
        if (!sinkUsesLocalOrParam) continue;

        return {
          targetFn: fn,
          sinkLine: c.lineNumber,
          sinkSnippet: c.snippet,
          sinkCwe: rule.cwe,
          sinkType: rule.sinkType,
          sinkCallee: c.callee,
          hopDepth: depth,
          sanitizersEncountered: combinedSanitized,
          hopChain: [],
        };
      }

      // 2. AST-detected SAST sink inside `fn`
      const astSastIssue = (astIssuesByFile.get(fn.filePath) || []).find(
        (iss) =>
          iss.category === 'SAST' &&
          (iss.cwe === 'CWE-89' ||
            iss.cwe === 'CWE-78' ||
            iss.cwe === 'CWE-95' ||
            iss.cwe === 'CWE-22' ||
            iss.cwe === 'CWE-79' ||
            iss.cwe === 'CWE-918') &&
          iss.lineNumber >= fn.startLine &&
          iss.lineNumber <= fn.endLine &&
          !(iss.cwe === 'CWE-89' && safeSql) &&
          !(iss.cwe === 'CWE-918' && safeSsrf)
      );
      if (astSastIssue) {
        const sinkType: TaintSinkType =
          astSastIssue.cwe === 'CWE-78'
            ? 'COMMAND_INJECTION'
            : astSastIssue.cwe === 'CWE-95'
              ? 'CODE_INJECTION'
              : astSastIssue.cwe === 'CWE-22'
                ? 'PATH_TRAVERSAL'
                : astSastIssue.cwe === 'CWE-79'
                  ? 'XSS'
                  : astSastIssue.cwe === 'CWE-918'
                    ? 'SSRF'
                    : 'SQL_INJECTION';
        if (!combinedSanitized.has(sinkType)) {
          return {
            targetFn: fn,
            sinkLine: astSastIssue.lineNumber,
            sinkSnippet: getLineSnippet(fn.filePath, astSastIssue.lineNumber),
            sinkCwe: astSastIssue.cwe || 'CWE-89',
            sinkType,
            sinkCallee: astSastIssue.ruleId,
            hopDepth: depth,
            sanitizersEncountered: combinedSanitized,
            hopChain: [],
          };
        }
      }

      // 3. Follow outgoing call-graph edges up to maxCallDepth
      for (const call of fn.callsMade) {
        if (DYNAMIC_DISPATCH_PATTERN.test(call.callee)) {
          recordIncompletePath({
            reason: 'DYNAMIC_CALL_DISPATCH',
            filePath: call.filePath,
            lineNumber: call.lineNumber,
            functionName: fn.name,
            calleeText: call.callee,
            confidenceImpact: 'INCONCLUSIVE',
            explanation: `Chamada dinâmica/indireta "${call.callee}" impede resolução estática exata do destino.`,
          });
          continue;
        }
        const nextTargets = resolveTargetFunctions(fn, call);
        for (const nextFn of nextTargets) {
          const sub = resolveDeepSink(nextFn, depth + 1, nextStack, combinedSanitized, budget);
          if (sub) {
            // Merge any sanitizers discovered locally
            for (const s of localSanitizers) {
              if (sanitizedVarNames.size > 0) sub.sanitizersEncountered.add(s);
            }
            return {
              ...sub,
              hopChain: [
                {
                  caller: fn,
                  callLine: call.lineNumber,
                  calleeText: call.callee,
                  snippet: call.snippet,
                },
                ...sub.hopChain,
              ],
            };
          }
        }
      }

      return null;
    };

    for (const parsed of sortedParseResults) {
      const fileContent = filesMap[parsed.filePath] || '';
      const fileAstIssues = parsed.issues;
      const sortedFns = [...parsed.functions].sort(
        (a, b) => a.startLine - b.startLine || a.name.localeCompare(b.name)
      );

      for (const fn of sortedFns) {
        if (parsed.filePath.toLowerCase().includes('test')) continue;

        const taintedVars = new Map<string, TaintedVarState>();

        for (const param of fn.params) {
          if (SOURCE_PARAM_HINT.test(param) || fn.isExported) {
            const snippet = getLineSnippet(parsed.filePath, fn.startLine);
            taintedVars.set(param, {
              originFile: parsed.filePath,
              originLine: fn.startLine,
              originFunction: fn.name,
              originSymbol: param,
              originSnippet: snippet,
              sanitizedFor: new Set<TaintSinkType>(),
              steps: [
                {
                  stepOrder: 1,
                  nodeType: 'SOURCE',
                  filePath: parsed.filePath,
                  lineNumber: fn.startLine,
                  symbolName: `${fn.name}(${param})`,
                  codeSnippet: snippet,
                  snippet,
                  explanation: `Parâmetro "${param}" recebido na fronteira de ${fn.name}() sem sanitização prévia comprovada.`,
                },
              ],
            });
          }
        }

        for (const binding of fn.variableBindings) {
          const matchingDeps = binding.dependencies.filter((d) => taintedVars.has(d));
          const helperCallDep = binding.dependencies.find((d) => fnReturnsTaint.get(d));

          if (matchingDeps.length === 0 && !helperCallDep) continue;
          const upstream =
            (matchingDeps[0] ? taintedVars.get(matchingDeps[0]) : undefined) ||
            Array.from(taintedVars.values())[0];
          if (!upstream) continue;

          const nextSanitizedFor = new Set(upstream.sanitizedFor);
          if (binding.isSanitized) {
            for (const sinkType of getSanitizedSinksForContext(binding.sanitizerContext)) {
              nextSanitizedFor.add(sinkType);
            }
          }

          const snippet = getLineSnippet(parsed.filePath, binding.lineNumber);
          const depLabel = matchingDeps[0] || helperCallDep || upstream.originSymbol;
          const explanation = binding.isSanitized
            ? `Variável "${binding.varName}" aplica "${binding.sanitizerName || 'sanitizador'}" (contexto: ${binding.sanitizerContext || 'parcial'}) sobre "${depLabel}".`
            : `Variável "${binding.varName}" propaga dado não sanitizado originado de "${depLabel}".`;

          taintedVars.set(binding.varName, {
            ...upstream,
            sanitizedFor: nextSanitizedFor,
            steps: [
              ...upstream.steps,
              {
                stepOrder: upstream.steps.length + 1,
                nodeType: 'PROPAGATOR',
                filePath: parsed.filePath,
                lineNumber: binding.lineNumber,
                symbolName: binding.varName,
                codeSnippet: snippet,
                snippet,
                explanation,
              },
            ],
          });
        }

        for (const call of fn.callsMade) {
          const matchedArg = call.argIdentifiers.find((id) => taintedVars.has(id));
          if (!matchedArg) continue;
          const taint = taintedVars.get(matchedArg)!;

          // Dynamic / indirect dispatch with tainted argument -> record INCONCLUSIVE incomplete path
          if (DYNAMIC_DISPATCH_PATTERN.test(call.callee)) {
            recordIncompletePath({
              reason: 'DYNAMIC_CALL_DISPATCH',
              filePath: call.filePath,
              lineNumber: call.lineNumber,
              functionName: fn.name,
              calleeText: call.callee,
              confidenceImpact: 'INCONCLUSIVE',
              explanation: `Argumento contaminado "${matchedArg}" passado para despacho dinâmico "${call.callee}" — destino não resolúvel estaticamente.`,
            });
            continue;
          }

          // Case A: Direct sink inside same function
          const sinkRule = SINK_RULES.find((r) => matchesSinkRule(r, call.callee, call.calleeBase));
          if (sinkRule) {
            if (taint.sanitizedFor.has(sinkRule.sinkType)) continue;
            if (sinkRule.sinkType === 'SQL_INJECTION' && functionHasSafeSqlHandling(fn, fileContent)) {
              continue;
            }
            if (sinkRule.sinkType === 'SSRF' && functionHasSafeSsrfGuard(fn, fileContent, call)) {
              continue;
            }
            if (sinkRule.sinkType === 'COMMAND_INJECTION' && functionHasSafeCommandGuard(fn, fileContent, call)) {
              continue;
            }
            if (sinkRule.sinkType === 'PATH_TRAVERSAL' && functionHasSafePathConfinement(fn, fileContent, call)) {
              continue;
            }
            const key = `${sinkRule.ruleId}|${call.filePath}|${call.lineNumber}`;
            if (!dedup.has(key)) {
              dedup.add(key);
              const flowSteps: CodeExecutionFlowStep[] = [
                ...taint.steps,
                {
                  stepOrder: taint.steps.length + 1,
                  nodeType: 'SANITIZER_MISSING',
                  filePath: call.filePath,
                  lineNumber: call.lineNumber,
                  symbolName: matchedArg,
                  codeSnippet: call.snippet,
                  snippet: call.snippet,
                  explanation: `Nenhuma sanitização válida para ${sinkRule.sinkType} interceptou "${matchedArg}" antes do sink.`,
                },
                {
                  stepOrder: taint.steps.length + 2,
                  nodeType: 'SINK',
                  filePath: call.filePath,
                  lineNumber: call.lineNumber,
                  symbolName: call.callee,
                  codeSnippet: call.snippet,
                  snippet: call.snippet,
                  explanation: `Dado alcança o sink perigoso "${call.callee}" (${sinkRule.cwe}).`,
                },
              ];

              taintIssues.push({
                ruleId: sinkRule.ruleId,
                title: sinkRule.title,
                description: `Fluxo de taint rastreado via AST de ${taint.originFile}:${taint.originLine} (${taint.originFunction}) até ${call.filePath}:${call.lineNumber} (${call.callee}).`,
                category: 'SAST',
                severity: sinkRule.sinkType === 'XSS' ? 'HIGH' : 'BLOCKER',
                cwe: sinkRule.cwe,
                filePath: call.filePath,
                lineNumber: call.lineNumber,
                endLineNumber: call.lineNumber,
                snippet: call.snippet,
                remediation: sinkRule.remediation,
                detectionMethod: 'TAINT_ANALYSIS',
                confidence: 'HIGH',
                effortMinutes: 35,
                executionFlows: flowSteps,
              });
            }
            continue;
          }

          // Case B: Interprocedural / Cross-file call-graph propagation (up to maxCallDepth hops)
          const targetFns = resolveTargetFunctions(fn, call);
          for (const targetFn of targetFns) {
            if (targetFn.filePath === fn.filePath && targetFn.name === fn.name) {
              cyclesDetected += 1;
              recordIncompletePath({
                reason: 'CYCLE_DETECTED',
                filePath: call.filePath,
                lineNumber: call.lineNumber,
                functionName: fn.name,
                calleeText: call.callee,
                confidenceImpact: 'LOW',
                explanation: `Auto-recursão direta detectada em "${fn.name}" (${call.filePath}:${call.lineNumber}).`,
              });
              continue;
            }

            const resolvedSink = resolveDeepSink(
              targetFn,
              1,
              new Set([makeNodeId(fn)]),
              new Set(taint.sanitizedFor),
              { visited: 0 }
            );
            if (!resolvedSink) continue;
            if (
              taint.sanitizedFor.has(resolvedSink.sinkType) ||
              resolvedSink.sanitizersEncountered.has(resolvedSink.sinkType)
            ) {
              continue;
            }

            const ruleId =
              SINK_RULES.find((r) => r.sinkType === resolvedSink.sinkType)?.ruleId || 'taint:S3649';
            const key = `${ruleId}|${resolvedSink.targetFn.filePath}|${resolvedSink.sinkLine}|${fn.filePath}`;
            if (dedup.has(key)) continue;
            dedup.add(key);

            const flowSteps: CodeExecutionFlowStep[] = [
              ...taint.steps,
              {
                stepOrder: taint.steps.length + 1,
                nodeType: 'PROPAGATOR',
                filePath: call.filePath,
                lineNumber: call.lineNumber,
                symbolName: `${call.callee}(${matchedArg})`,
                codeSnippet: call.snippet,
                snippet: call.snippet,
                explanation: `Função "${fn.name}" propaga "${matchedArg}" para "${targetFn.name}" em ${targetFn.filePath}.`,
              },
            ];

            for (const hop of resolvedSink.hopChain) {
              flowSteps.push({
                stepOrder: flowSteps.length + 1,
                nodeType: 'PROPAGATOR',
                filePath: hop.caller.filePath,
                lineNumber: hop.callLine,
                symbolName: hop.calleeText,
                codeSnippet: hop.snippet,
                snippet: hop.snippet,
                explanation: `Propagação interprocedural intermediária de "${hop.caller.name}" para "${hop.calleeText}".`,
              });
            }

            flowSteps.push(
              {
                stepOrder: flowSteps.length + 1,
                nodeType: 'SANITIZER_MISSING',
                filePath: resolvedSink.targetFn.filePath,
                lineNumber: resolvedSink.targetFn.startLine,
                symbolName: resolvedSink.targetFn.params[0] || matchedArg,
                codeSnippet: getLineSnippet(resolvedSink.targetFn.filePath, resolvedSink.targetFn.startLine),
                snippet: getLineSnippet(resolvedSink.targetFn.filePath, resolvedSink.targetFn.startLine),
                explanation: `Entrada entra em "${resolvedSink.targetFn.name}" sem parametrização ou sanitização compatível com ${resolvedSink.sinkType}.`,
              },
              {
                stepOrder: flowSteps.length + 2,
                nodeType: 'SINK',
                filePath: resolvedSink.targetFn.filePath,
                lineNumber: resolvedSink.sinkLine,
                symbolName: resolvedSink.sinkCallee,
                codeSnippet: resolvedSink.sinkSnippet,
                snippet: resolvedSink.sinkSnippet,
                explanation: `Sink vulnerável executado em ${resolvedSink.targetFn.filePath}:${resolvedSink.sinkLine} (${resolvedSink.sinkCwe}, profundidade=${resolvedSink.hopDepth} saltos).`,
              }
            );

            // Calibrate confidence conservatively for deep multi-hop chains (> 4 hops)
            const confidence: 'HIGH' | 'MEDIUM' = resolvedSink.hopDepth > 4 ? 'MEDIUM' : 'HIGH';

            taintIssues.push({
              ruleId,
              title:
                resolvedSink.sinkType === 'COMMAND_INJECTION'
                  ? `Command Injection interprocedural (${fn.name} → ${resolvedSink.targetFn.name})`
                  : resolvedSink.sinkType === 'PATH_TRAVERSAL'
                    ? `Path Traversal interprocedural (${fn.name} → ${resolvedSink.targetFn.name})`
                    : resolvedSink.sinkType === 'XSS'
                      ? `Cross-Site Scripting interprocedural (${fn.name} → ${resolvedSink.targetFn.name})`
                      : resolvedSink.sinkType === 'SSRF'
                        ? `SSRF interprocedural (${fn.name} → ${resolvedSink.targetFn.name})`
                        : `SQL Injection interprocedural (${fn.name} → ${resolvedSink.targetFn.name})`,
              description: `Fluxo Source-to-Sink cross-file (${resolvedSink.hopDepth} salto(s)) rastreado de ${taint.originFile}:${taint.originLine} até ${resolvedSink.targetFn.filePath}:${resolvedSink.sinkLine}.`,
              category: 'SAST',
              severity: resolvedSink.sinkType === 'XSS' ? 'HIGH' : 'BLOCKER',
              cwe: resolvedSink.sinkCwe,
              filePath: resolvedSink.targetFn.filePath,
              lineNumber: resolvedSink.sinkLine,
              endLineNumber: resolvedSink.sinkLine,
              snippet: resolvedSink.sinkSnippet,
              remediation:
                SINK_RULES.find((r) => r.sinkType === resolvedSink.sinkType)?.remediation ||
                'Aplicar validação e parametrização estrita antes do sink.',
              detectionMethod: 'TAINT_ANALYSIS',
              confidence,
              effortMinutes: 35,
              executionFlows: flowSteps,
            });
          }
        }
      }

      const injectionCwes = new Set(['CWE-89', 'CWE-78', 'CWE-95', 'CWE-22', 'CWE-79', 'CWE-918']);
      for (const iss of fileAstIssues) {
        if (iss.category === 'SAST' && (!iss.executionFlows || iss.executionFlows.length === 0)) {
          const enclosingFn = parsed.functions.find(
            (f) => iss.lineNumber >= f.startLine && iss.lineNumber <= f.endLine
          );
          if (enclosingFn && enclosingFn.params.length > 0) {
            iss.executionFlows = [
              {
                stepOrder: 1,
                nodeType: 'SOURCE',
                filePath: parsed.filePath,
                lineNumber: enclosingFn.startLine,
                symbolName: `${enclosingFn.name}(${enclosingFn.params.join(', ')})`,
                codeSnippet: getLineSnippet(parsed.filePath, enclosingFn.startLine),
                snippet: getLineSnippet(parsed.filePath, enclosingFn.startLine),
                explanation: `Entrada recebida pelos parâmetros de ${enclosingFn.name}().`,
              },
              {
                stepOrder: 2,
                nodeType: 'SANITIZER_MISSING',
                filePath: parsed.filePath,
                lineNumber: iss.lineNumber,
                symbolName: enclosingFn.params[0] || 'input',
                codeSnippet: iss.snippet,
                snippet: iss.snippet,
                explanation: 'Ausência de validação/parametrização antes do ponto de uso.',
              },
              {
                stepOrder: 3,
                nodeType: 'SINK',
                filePath: parsed.filePath,
                lineNumber: iss.lineNumber,
                symbolName: iss.ruleId,
                codeSnippet: iss.snippet,
                snippet: iss.snippet,
                explanation: `${iss.title} (${iss.cwe}) na linha ${iss.lineNumber}.`,
              },
            ];
          } else if (iss.cwe && injectionCwes.has(iss.cwe)) {
            iss.executionFlows = [
              {
                stepOrder: 1,
                nodeType: 'SOURCE',
                filePath: parsed.filePath,
                lineNumber: iss.lineNumber,
                symbolName: 'untrusted_input',
                codeSnippet: iss.snippet,
                snippet: iss.snippet,
                explanation: 'Entrada externa ou expressão dinâmica identificada diretamente no bloco.',
              },
              {
                stepOrder: 2,
                nodeType: 'SANITIZER_MISSING',
                filePath: parsed.filePath,
                lineNumber: iss.lineNumber,
                symbolName: iss.ruleId,
                codeSnippet: iss.snippet,
                snippet: iss.snippet,
                explanation: 'Sem sanitização ou parametrização comprovada para o contexto do sink.',
              },
              {
                stepOrder: 3,
                nodeType: 'SINK',
                filePath: parsed.filePath,
                lineNumber: iss.lineNumber,
                symbolName: iss.ruleId,
                codeSnippet: iss.snippet,
                snippet: iss.snippet,
                explanation: `${iss.title} (${iss.cwe}) na linha ${iss.lineNumber}.`,
              },
            ];
          }
        }
      }
    }

    const elapsedMs = Math.max(0, Math.round(performance.now() - startedMs));
    return {
      issues: taintIssues,
      callGraph: {
        nodes: graphNodes,
        edges: graphEdges,
        dynamicCallSites,
        cyclesDetected,
        truncatedPaths,
      },
      incompletePaths,
      stats: {
        maxDepthConfigured: maxCallDepth,
        maxDepthObserved,
        nodesCount: graphNodes.length,
        edgesCount: graphEdges.length,
        cyclesDetected,
        truncatedPaths,
        dynamicCallSites,
        elapsedMs,
      },
    };
  }
}
