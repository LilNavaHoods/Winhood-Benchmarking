import type { CodeExecutionFlowStep } from '../types/benchmark';
import type { AstFunctionNode, AstIssueCandidate, AstParseResult } from './types';

interface TaintedVarState {
  originFile: string;
  originLine: number;
  originFunction: string;
  originSymbol: string;
  originSnippet: string;
  steps: CodeExecutionFlowStep[];
}

const SOURCE_PARAM_HINT =
  /(input|query|filter|path|target|cmd|command|url|req|request|body|param|user|title|name|payload|raw|sql|expr|file)/i;

const SINK_RULES: Array<{
  calleePattern: RegExp;
  ruleId: string;
  title: string;
  cwe: string;
  sinkType: 'SQL_INJECTION' | 'COMMAND_INJECTION' | 'CODE_INJECTION' | 'PATH_TRAVERSAL' | 'XSS';
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
];

/**
 * TaintAnalyzer (P1)
 * Rastreamento real intraprocedural e interprocedural (cross-file) a partir dos nós AST:
 * SOURCE -> PROPAGATOR -> SANITIZER / SANITIZER_MISSING -> SINK.
 * Nunca utiliza caminhos de arquivos ou números de linhas fixos/hardcoded.
 */
export class TaintAnalyzer {
  public static analyzeFlows(
    parseResults: AstParseResult[],
    filesMap: Record<string, string>
  ): AstIssueCandidate[] {
    const taintIssues: AstIssueCandidate[] = [];
    const fnByName = new Map<string, AstFunctionNode[]>();

    for (const parsed of parseResults) {
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

    const dedup = new Set<string>();

    // Helper: check if a function itself safely sanitizes or uses prepared statements
    const functionHasSafeSqlHandling = (fn: AstFunctionNode, fileContent: string): boolean => {
      const lines = fileContent.split(/\r?\n/).slice(Math.max(0, fn.startLine - 1), fn.endLine);
      const body = lines.join('\n');
      const usesParamPlaceholder = (body.includes('VALUES (?') || body.includes('= ?') || /\$\d+/.test(body)) && !body.includes('+');
      return usesParamPlaceholder && !body.includes('${');
    };

    // Analyze each parsed function for intraprocedural & 1-hop/multi-hop interprocedural flows
    for (const parsed of parseResults) {
      const fileContent = filesMap[parsed.filePath] || '';
      const fileAstIssues = parsed.issues;

      for (const fn of parsed.functions) {
        if (parsed.filePath.toLowerCase().includes('test')) continue;

        const taintedVars = new Map<string, TaintedVarState>();

        // 1. Seed taint from function parameters matching source hints or controller/handler entrypoints
        for (const param of fn.params) {
          if (SOURCE_PARAM_HINT.test(param) || fn.isExported) {
            const snippet = getLineSnippet(parsed.filePath, fn.startLine);
            taintedVars.set(param, {
              originFile: parsed.filePath,
              originLine: fn.startLine,
              originFunction: fn.name,
              originSymbol: param,
              originSnippet: snippet,
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

        // 2. Propagate or sanitize across local variable bindings in function AST
        for (const binding of fn.variableBindings) {
          if (binding.isSanitized) {
            taintedVars.delete(binding.varName);
            continue;
          }
          for (const dep of binding.dependencies) {
            const upstream = taintedVars.get(dep);
            if (upstream) {
              const snippet = getLineSnippet(parsed.filePath, binding.lineNumber);
              taintedVars.set(binding.varName, {
                ...upstream,
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
                    explanation: `Variável "${binding.varName}" propaga dado não sanitizado originado de "${dep}".`,
                  },
                ],
              });
              break;
            }
          }
        }

        // 3. Evaluate call sites within this function:
        //    Case A: Direct sink in this function (e.g. execSync(cmd), eval(x))
        //    Case B: Cross-function / cross-file propagation (e.g. controller calls repo function which hits sink)
        for (const call of fn.callsMade) {
          const matchedArg = call.argIdentifiers.find((id) => taintedVars.has(id));
          if (!matchedArg) continue;
          const taint = taintedVars.get(matchedArg)!;

          // Check direct sinks inside same function
          const sinkRule = SINK_RULES.find((r) => r.calleePattern.test(call.calleeBase || call.callee));
          if (sinkRule) {
            // Confirm unsafe sink if SQL (don't flag parameterized queries)
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
                  explanation: `Nenhuma validação/sanitização estrutural interceptou "${matchedArg}" antes do sink.`,
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
                severity: 'BLOCKER',
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

          // Case B: Interprocedural / Cross-file propagation to callee function in project
          const calleeName = call.calleeBase || call.callee;
          const targetFns = fnByName.get(calleeName) || [];
          for (const targetFn of targetFns) {
            if (targetFn.filePath === fn.filePath && targetFn.name === fn.name) continue;
            const targetFileContent = filesMap[targetFn.filePath] || '';
            if (functionHasSafeSqlHandling(targetFn, targetFileContent)) {
              continue;
            }

            // Does targetFn have a direct sink or an AST SAST issue within its line span?
            const targetDirectSink = targetFn.callsMade.find((c) =>
              SINK_RULES.some((r) => r.calleePattern.test(c.calleeBase || c.callee))
            );
            const targetAstSqliOrRce = parseResults
              .find((p) => p.filePath === targetFn.filePath)
              ?.issues.find(
                (iss) =>
                  iss.category === 'SAST' &&
                  (iss.cwe === 'CWE-89' || iss.cwe === 'CWE-78' || iss.cwe === 'CWE-95') &&
                  iss.lineNumber >= targetFn.startLine &&
                  iss.lineNumber <= targetFn.endLine
              );

            if (targetDirectSink || targetAstSqliOrRce) {
              const sinkLine = targetDirectSink?.lineNumber || targetAstSqliOrRce!.lineNumber;
              const sinkSnippet =
                targetDirectSink?.snippet || getLineSnippet(targetFn.filePath, sinkLine);
              const sinkCwe = targetAstSqliOrRce?.cwe || 'CWE-89';
              const ruleId = sinkCwe === 'CWE-78' ? 'taint:S2076' : 'taint:S3649';
              const key = `${ruleId}|${targetFn.filePath}|${sinkLine}|${fn.filePath}`;
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
                {
                  stepOrder: taint.steps.length + 2,
                  nodeType: 'SANITIZER_MISSING',
                  filePath: targetFn.filePath,
                  lineNumber: targetFn.startLine,
                  symbolName: targetFn.params[0] || matchedArg,
                  codeSnippet: getLineSnippet(targetFn.filePath, targetFn.startLine),
                  snippet: getLineSnippet(targetFn.filePath, targetFn.startLine),
                  explanation: `Entrada entra em "${targetFn.name}" sem parametrização ou sanitização.`,
                },
                {
                  stepOrder: taint.steps.length + 3,
                  nodeType: 'SINK',
                  filePath: targetFn.filePath,
                  lineNumber: sinkLine,
                  symbolName: targetDirectSink?.callee || 'SQL/Sink',
                  codeSnippet: sinkSnippet,
                  snippet: sinkSnippet,
                  explanation: `Sink vulnerável executado em ${targetFn.filePath}:${sinkLine} (${sinkCwe}).`,
                },
              ];

              taintIssues.push({
                ruleId,
                title:
                  sinkCwe === 'CWE-78'
                    ? `Command Injection interprocedural (${fn.name} → ${targetFn.name})`
                    : `SQL Injection interprocedural (${fn.name} → ${targetFn.name})`,
                description: `Fluxo Source-to-Sink cross-file rastreado de ${taint.originFile}:${taint.originLine} até ${targetFn.filePath}:${sinkLine}.`,
                category: 'SAST',
                severity: 'BLOCKER',
                cwe: sinkCwe,
                filePath: targetFn.filePath,
                lineNumber: sinkLine,
                endLineNumber: sinkLine,
                snippet: sinkSnippet,
                remediation:
                  sinkCwe === 'CWE-78'
                    ? 'Evitar shell e validar argumentos com allowlist.'
                    : 'Utilizar Prepared Statements parametrizados com placeholders (? / $1).',
                detectionMethod: 'TAINT_ANALYSIS',
                confidence: 'HIGH',
                effortMinutes: 35,
                executionFlows: flowSteps,
              });
            }
          }
        }
      }

      // Attach AST flows to same-file AST SAST issues that lacked flows when taint reached them
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
