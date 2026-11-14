import type { CodeExecutionFlowStep } from '../types/benchmark';
import type { AstFunctionNode, AstIssueCandidate, AstParseResult } from './types';

type TaintSinkType =
  | 'SQL_INJECTION'
  | 'COMMAND_INJECTION'
  | 'CODE_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'XSS';

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
  /(input|query|filter|path|target|cmd|command|url|req|request|body|param|user|title|name|payload|raw|sql|expr|file|html|tpl)/i;

const SINK_RULES: Array<{
  calleePattern: RegExp;
  ruleId: string;
  title: string;
  cwe: string;
  sinkType: TaintSinkType;
  remediation: string;
}> = [
  {
    calleePattern: /^(execSync|exec|system|popen)$/i,
    ruleId: 'taint:S2076',
    title: 'Fluxo Taint interprocedural até execução de comando OS (CWE-78)',
    cwe: 'CWE-78',
    sinkType: 'COMMAND_INJECTION',
    remediation: 'Substituir por execFile/spawn com shell: false e allowlist de argumentos.',
  },
  {
    calleePattern: /^(eval|Function)$/i,
    ruleId: 'taint:S1523',
    title: 'Fluxo Taint até avaliação dinâmica de código (CWE-95)',
    cwe: 'CWE-95',
    sinkType: 'CODE_INJECTION',
    remediation: 'Eliminar eval/new Function e validar entrada contra esquema estrito.',
  },
  {
    calleePattern: /^(query|execute|raw|executeQuery|ExecuteReader|queryVaultEntriesRaw)$/i,
    ruleId: 'taint:S3649',
    title: 'Fluxo Taint até sink de consulta SQL (CWE-89)',
    cwe: 'CWE-89',
    sinkType: 'SQL_INJECTION',
    remediation: 'Utilizar Prepared Statements parametrizados (? / $1) em vez de concatenação.',
  },
  {
    calleePattern: /^(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)$/i,
    ruleId: 'taint:S2083',
    title: 'Fluxo Taint até operação de sistema de arquivos (Path Traversal CWE-22)',
    cwe: 'CWE-22',
    sinkType: 'PATH_TRAVERSAL',
    remediation: 'Normalizar com path.basename/path.resolve e validar fronteira de diretório raiz permitido.',
  },
  {
    calleePattern: /^(renderHtml|sendHtml|writeHtml|dangerouslySetInnerHTML)$/i,
    ruleId: 'taint:S5131',
    title: 'Fluxo Taint até renderização HTML não escapada (XSS CWE-79)',
    cwe: 'CWE-79',
    sinkType: 'XSS',
    remediation: 'Aplicar escape HTML contextual (escapeHtml/DOMPurify) antes de renderizar conteúdo.',
  },
];

function getSanitizedSinksForContext(
  ctx: NonNullable<AstFunctionNode['variableBindings'][number]['sanitizerContext']> | undefined
): TaintSinkType[] {
  switch (ctx) {
    case 'NUMERIC':
      return ['SQL_INJECTION', 'COMMAND_INJECTION', 'CODE_INJECTION', 'PATH_TRAVERSAL', 'XSS'];
    case 'SQL_PREPARED':
      return ['SQL_INJECTION'];
    case 'HTML_ESCAPE':
      return ['XSS'];
    case 'PATH_BASENAME':
      return ['PATH_TRAVERSAL'];
    case 'URL_ENCODE':
      // encodeURIComponent ONLY encodes URL query components; it MUST NOT clear SQL/CMD/CODE/PATH taint!
      return [];
    case 'CRYPTO_KDF':
      return ['SQL_INJECTION', 'XSS'];
    case 'GENERIC_SCHEMA':
      return ['SQL_INJECTION', 'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'XSS'];
    default:
      return [];
  }
}

/**
 * TaintAnalyzer (P1/P2)
 * Rastreamento intraprocedural e interprocedural (até 2 saltos + retorno de helper)
 * com sanitização sensível ao contexto de sink:
 * - encodeURIComponent não neutraliza SQLi / Command Injection.
 * - Number/parseInt neutralizam numericamente SQL/Shell/Path.
 * - escapeHtml neutraliza apenas XSS.
 * - basename neutraliza apenas Path Traversal.
 */
export class TaintAnalyzer {
  public static analyzeFlows(
    parseResults: AstParseResult[],
    filesMap: Record<string, string>
  ): AstIssueCandidate[] {
    const taintIssues: AstIssueCandidate[] = [];
    const fnByName = new Map<string, AstFunctionNode[]>();
    const astIssuesByFile = new Map<string, AstIssueCandidate[]>();

    for (const parsed of parseResults) {
      astIssuesByFile.set(parsed.filePath, parsed.issues);
      for (const fn of parsed.functions) {
        const list = fnByName.get(fn.name) || [];
        list.push(fn);
        fnByName.set(fn.name, list);
      }
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
        (body.includes('VALUES (?') || body.includes('= ?') || /\$\d+/.test(body)) && !body.includes('+');
      return usesParamPlaceholder && !body.includes('${');
    };

    // Precompute functions whose return values propagate tainted parameters (for helper return propagation)
    const fnReturnsTaint = new Map<string, boolean>();
    for (const parsed of parseResults) {
      for (const fn of parsed.functions) {
        if (fn.returnValues.length === 0) continue;
        const paramSet = new Set(fn.params);
        const taintedLocal = new Set<string>(fn.params);
        for (const b of fn.variableBindings) {
          if (b.isSanitized && getSanitizedSinksForContext(b.sanitizerContext).length >= 3) {
            taintedLocal.delete(b.varName);
          } else if (b.dependencies.some((d) => taintedLocal.has(d) || paramSet.has(d))) {
            taintedLocal.add(b.varName);
          }
        }
        if (fn.returnValues.some((rv) => taintedLocal.has(rv))) {
          fnReturnsTaint.set(fn.name, true);
        }
      }
    }

    const dedup = new Set<string>();

    const resolveDeepSink = (
      fn: AstFunctionNode,
      depth: number,
      visited: Set<string>
    ): {
      targetFn: AstFunctionNode;
      sinkLine: number;
      sinkSnippet: string;
      sinkCwe: string;
      sinkType: TaintSinkType;
      sinkCallee: string;
      hopChain: Array<{ caller: AstFunctionNode; callLine: number; calleeText: string; snippet: string }>;
    } | null => {
      if (depth > 2) return null;
      const visitKey = `${fn.filePath}:${fn.name}`;
      if (visited.has(visitKey)) return null;
      visited.add(visitKey);

      const fileContent = filesMap[fn.filePath] || '';
      const safeSql = functionHasSafeSqlHandling(fn, fileContent);

      const directSinkCall = fn.callsMade.find((c) => {
        const rule = SINK_RULES.find((r) => r.calleePattern.test(c.calleeBase || c.callee));
        if (!rule) return false;
        if (rule.sinkType === 'SQL_INJECTION' && safeSql) return false;
        return true;
      });
      if (directSinkCall) {
        const rule = SINK_RULES.find((r) => r.calleePattern.test(directSinkCall.calleeBase || directSinkCall.callee))!;
        return {
          targetFn: fn,
          sinkLine: directSinkCall.lineNumber,
          sinkSnippet: directSinkCall.snippet,
          sinkCwe: rule.cwe,
          sinkType: rule.sinkType,
          sinkCallee: directSinkCall.callee,
          hopChain: [],
        };
      }

      const astSastIssue = (astIssuesByFile.get(fn.filePath) || []).find(
        (iss) =>
          iss.category === 'SAST' &&
          (iss.cwe === 'CWE-89' || iss.cwe === 'CWE-78' || iss.cwe === 'CWE-95' || iss.cwe === 'CWE-22' || iss.cwe === 'CWE-79') &&
          iss.lineNumber >= fn.startLine &&
          iss.lineNumber <= fn.endLine &&
          !(iss.cwe === 'CWE-89' && safeSql)
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
                  : 'SQL_INJECTION';
        return {
          targetFn: fn,
          sinkLine: astSastIssue.lineNumber,
          sinkSnippet: getLineSnippet(fn.filePath, astSastIssue.lineNumber),
          sinkCwe: astSastIssue.cwe,
          sinkType,
          sinkCallee: astSastIssue.ruleId,
          hopChain: [],
        };
      }

      if (depth < 2) {
        for (const call of fn.callsMade) {
          const nextName = call.calleeBase || call.callee;
          const nextTargets = fnByName.get(nextName) || [];
          for (const nextFn of nextTargets) {
            const sub = resolveDeepSink(nextFn, depth + 1, new Set(visited));
            if (sub) {
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
      }

      return null;
    };

    for (const parsed of parseResults) {
      const fileContent = filesMap[parsed.filePath] || '';
      const fileAstIssues = parsed.issues;

      for (const fn of parsed.functions) {
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

          // Case A: Direct sink inside same function
          const sinkRule = SINK_RULES.find((r) => r.calleePattern.test(call.calleeBase || call.callee));
          if (sinkRule) {
            if (taint.sanitizedFor.has(sinkRule.sinkType)) continue;
            if (sinkRule.sinkType === 'SQL_INJECTION' && functionHasSafeSqlHandling(fn, fileContent)) {
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

          // Case B: Interprocedural / Cross-file propagation (1 or 2 hops)
          const calleeName = call.calleeBase || call.callee;
          const targetFns = fnByName.get(calleeName) || [];
          for (const targetFn of targetFns) {
            if (targetFn.filePath === fn.filePath && targetFn.name === fn.name) continue;

            const resolvedSink = resolveDeepSink(targetFn, 1, new Set([`${fn.filePath}:${fn.name}`]));
            if (!resolvedSink) continue;
            if (taint.sanitizedFor.has(resolvedSink.sinkType)) continue;

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
                explanation: `Sink vulnerável executado em ${resolvedSink.targetFn.filePath}:${resolvedSink.sinkLine} (${resolvedSink.sinkCwe}).`,
              }
            );

            taintIssues.push({
              ruleId,
              title:
                resolvedSink.sinkType === 'COMMAND_INJECTION'
                  ? `Command Injection interprocedural (${fn.name} → ${resolvedSink.targetFn.name})`
                  : resolvedSink.sinkType === 'PATH_TRAVERSAL'
                    ? `Path Traversal interprocedural (${fn.name} → ${resolvedSink.targetFn.name})`
                    : resolvedSink.sinkType === 'XSS'
                      ? `Cross-Site Scripting interprocedural (${fn.name} → ${resolvedSink.targetFn.name})`
                      : `SQL Injection interprocedural (${fn.name} → ${resolvedSink.targetFn.name})`,
              description: `Fluxo Source-to-Sink cross-file rastreado de ${taint.originFile}:${taint.originLine} até ${resolvedSink.targetFn.filePath}:${resolvedSink.sinkLine}.`,
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
              confidence: 'HIGH',
              effortMinutes: 35,
              executionFlows: flowSteps,
            });
          }
        }
      }

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
          }
        }
      }
    }

    return taintIssues;
  }
}
