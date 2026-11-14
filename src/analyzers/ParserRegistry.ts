import { parse as babelParse, type ParserPlugin } from '@babel/parser';
import type {
  AstCallSite,
  AstFunctionNode,
  AstImportNode,
  AstIssueCandidate,
  AstParseResult,
  SupportedAstLanguage,
} from './types';

function shannonEntropy(input: string): number {
  if (!input || input.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of input) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const SECRET_IDENTIFIER_HINT =
  /(secret|password|passwd|masterkey|master_key|apikey|api_key|privatekey|private_key|auth_token|access_token|jwt_secret|db_pass)/i;
const PLACEHOLDER_SECRET_HINT =
  /^(example|placeholder|changeme|your[_-]|dummy|mock|test[_-]?token|xxx+|000+)$/i;

const SANITIZER_CONTEXT_MAP = new Map<
  string,
  'NUMERIC' | 'URL_ENCODE' | 'HTML_ESCAPE' | 'PATH_BASENAME' | 'CRYPTO_KDF' | 'SQL_PREPARED' | 'GENERIC_SCHEMA'
>([
  ['parseInt', 'NUMERIC'],
  ['Number', 'NUMERIC'],
  ['parseFloat', 'NUMERIC'],
  ['Boolean', 'NUMERIC'],
  ['encodeURIComponent', 'URL_ENCODE'],
  ['encodeURI', 'URL_ENCODE'],
  ['escapeHtml', 'HTML_ESCAPE'],
  ['sanitizeHtml', 'HTML_ESCAPE'],
  ['basename', 'PATH_BASENAME'],
  ['pbkdf2Sync', 'CRYPTO_KDF'],
  ['scryptSync', 'CRYPTO_KDF'],
  ['createHmac', 'CRYPTO_KDF'],
  ['zodParse', 'GENERIC_SCHEMA'],
  ['sanitize', 'GENERIC_SCHEMA'],
]);

function classifySanitizerContext(
  calleeTxt: string,
  shortCallee: string
):
  | 'NUMERIC'
  | 'URL_ENCODE'
  | 'HTML_ESCAPE'
  | 'PATH_BASENAME'
  | 'CRYPTO_KDF'
  | 'SQL_PREPARED'
  | 'GENERIC_SCHEMA'
  | undefined {
  const direct = SANITIZER_CONTEXT_MAP.get(shortCallee) || SANITIZER_CONTEXT_MAP.get(calleeTxt);
  if (direct) return direct;
  if (/escapeHtml|sanitizeHtml/i.test(calleeTxt)) return 'HTML_ESCAPE';
  if (/prepared|parameterized|prepareStatement/i.test(calleeTxt)) return 'SQL_PREPARED';
  if (/sanitize|allowlist|validateSchema|zod/i.test(calleeTxt)) return 'GENERIC_SCHEMA';
  return undefined;
}

const SQL_KEYWORD_PATTERN = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|MERGE|EXEC)\b/i;

interface SimpleToken {
  type: 'IDENT' | 'KEYWORD' | 'STRING' | 'NUMBER' | 'PUNCT' | 'COMMENT';
  value: string;
  line: number;
}

function tokenizeGenericSource(
  content: string,
  keywords: Set<string>,
  hashComments: boolean
): SimpleToken[] {
  const tokens: SimpleToken[] = [];
  let i = 0;
  let line = 1;
  const n = content.length;

  while (i < n) {
    const ch = content[i]!;
    const next = content[i + 1] || '';

    if (ch === '\n') {
      line += 1;
      i += 1;
      continue;
    }
    if (/\s/.test(ch)) {
      i += 1;
      continue;
    }

    // Line comments
    if ((ch === '/' && next === '/') || (hashComments && ch === '#') || (ch === '-' && next === '-')) {
      const startLine = line;
      let buf = '';
      while (i < n && content[i] !== '\n') {
        buf += content[i];
        i += 1;
      }
      tokens.push({ type: 'COMMENT', value: buf, line: startLine });
      continue;
    }

    // Block comments
    if (ch === '/' && next === '*') {
      const startLine = line;
      let buf = '/*';
      i += 2;
      while (i < n && !(content[i] === '*' && content[i + 1] === '/')) {
        if (content[i] === '\n') line += 1;
        buf += content[i];
        i += 1;
      }
      if (i < n) {
        buf += '*/';
        i += 2;
      }
      tokens.push({ type: 'COMMENT', value: buf, line: startLine });
      continue;
    }

    // Strings (' " `)
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      const startLine = line;
      let buf = quote;
      i += 1;
      while (i < n) {
        const c = content[i]!;
        if (c === '\n') line += 1;
        if (c === '\\' && i + 1 < n) {
          buf += c + content[i + 1];
          i += 2;
          continue;
        }
        buf += c;
        i += 1;
        if (c === quote) break;
      }
      tokens.push({ type: 'STRING', value: buf, line: startLine });
      continue;
    }

    // Numbers
    if (/[0-9]/.test(ch)) {
      let buf = '';
      const startLine = line;
      while (i < n && /[0-9a-fA-Fx._]/.test(content[i]!)) {
        buf += content[i];
        i += 1;
      }
      tokens.push({ type: 'NUMBER', value: buf, line: startLine });
      continue;
    }

    // Identifiers / keywords
    if (/[a-zA-Z_$]/.test(ch)) {
      let buf = '';
      const startLine = line;
      while (i < n && /[a-zA-Z0-9_$]/.test(content[i]!)) {
        buf += content[i];
        i += 1;
      }
      tokens.push({
        type: keywords.has(buf) || keywords.has(buf.toUpperCase()) ? 'KEYWORD' : 'IDENT',
        value: buf,
        line: startLine,
      });
      continue;
    }

    tokens.push({ type: 'PUNCT', value: ch, line });
    i += 1;
  }

  return tokens;
}

/**
 * ParserRegistry (P1)
 * - Uses real TypeScript Compiler AST (`typescript` package) for TS/TSX/JS/JSX.
 * - Uses structural token-stream AST builders for Python, Java, C#, Go, Rust, SQL.
 * - Only marks `astParsed = true` when a genuine structural parse was performed.
 */
export class ParserRegistry {
  public static detectLanguage(filePath: string): SupportedAstLanguage {
    const lower = filePath.toLowerCase();
    if (lower.endsWith('.ts') || lower.endsWith('.tsx')) return 'TypeScript';
    if (lower.endsWith('.js') || lower.endsWith('.jsx') || lower.endsWith('.mjs') || lower.endsWith('.cjs'))
      return 'JavaScript';
    if (lower.endsWith('.py')) return 'Python';
    if (lower.endsWith('.java')) return 'Java';
    if (lower.endsWith('.cs')) return 'C#';
    if (lower.endsWith('.go')) return 'Go';
    if (lower.endsWith('.rs')) return 'Rust';
    if (lower.endsWith('.sql')) return 'SQL';
    return 'Other';
  }

  public static parseFile(filePath: string, content: string): AstParseResult {
    const language = ParserRegistry.detectLanguage(filePath);
    if (language === 'TypeScript' || language === 'JavaScript') {
      return ParserRegistry.parseTypeScriptOrJsAst(filePath, content, language);
    }
    if (language === 'Python') {
      return ParserRegistry.parsePythonStructuralAst(filePath, content);
    }
    if (language === 'Java' || language === 'C#' || language === 'Go' || language === 'Rust') {
      return ParserRegistry.parseBraceLanguageStructuralAst(filePath, content, language);
    }
    if (language === 'SQL') {
      return ParserRegistry.parseSqlAst(filePath, content);
    }

    const lines = content.split(/\r?\n/);
    return {
      filePath,
      language,
      astParsed: false,
      parserKind: 'UNSUPPORTED',
      errorCount: 0,
      parserEngine: 'UNSUPPORTED_EXTENSION',
      loc: lines.filter((l) => l.trim().length > 0).length,
      cyclomaticComplexity: 1,
      cognitiveComplexity: 0,
      imports: [],
      functions: [],
      callSites: [],
      issues: [],
      hasAuditSignals: false,
      hasCryptoSignals: false,
      hasWeakCryptoSignals: false,
      hasPreparedStatementSignals: false,
    };
  }

  private static parseTypeScriptOrJsAst(
    filePath: string,
    content: string,
    language: 'TypeScript' | 'JavaScript'
  ): AstParseResult {
    const lines = content.split(/\r?\n/);
    const getSnippet = (lineNo: number): string => (lines[lineNo - 1] || '').trim();
    const getLine = (node: any): number => node?.loc?.start?.line ?? 1;
    const getEndLine = (node: any): number => node?.loc?.end?.line ?? getLine(node);
    const getSourceText = (node: any): string =>
      typeof node?.start === 'number' && typeof node?.end === 'number'
        ? content.slice(node.start, node.end)
        : '';

    const isTs = language === 'TypeScript';
    const isJsx =
      filePath.toLowerCase().endsWith('.tsx') ||
      filePath.toLowerCase().endsWith('.jsx') ||
      (language === 'JavaScript' && /<[A-Z][A-Za-z0-9]*[\s/>]/.test(content));

    let ast: any;
    const parserPlugins: ParserPlugin[] = ['decorators-legacy'];
    if (isTs) parserPlugins.push('typescript');
    if (isJsx) parserPlugins.push('jsx');
    try {
      ast = babelParse(content, {
        sourceType: 'unambiguous',
        errorRecovery: true,
        plugins: parserPlugins,
      });
    } catch {
      return {
        filePath,
        language,
        astParsed: false,
        parserKind: 'UNSUPPORTED',
        errorCount: 1,
        parserEngine: 'babel-parser-parse-error',
        loc: lines.filter((l) => l.trim().length > 0 && !l.trim().startsWith('//')).length,
        cyclomaticComplexity: 1,
        cognitiveComplexity: 0,
        imports: [],
        functions: [],
        callSites: [],
        issues: [],
        hasAuditSignals: false,
        hasCryptoSignals: false,
        hasWeakCryptoSignals: false,
        hasPreparedStatementSignals: false,
      };
    }

    const walkAny = (node: any, cb: (n: any) => boolean | void): void => {
      if (!node || typeof node !== 'object') return;
      if (typeof node.type === 'string') {
        const res = cb(node);
        if (res === false) return;
      }
      for (const key of Object.keys(node)) {
        if (
          key === 'loc' ||
          key === 'start' ||
          key === 'end' ||
          key === 'extra' ||
          key === 'leadingComments' ||
          key === 'trailingComments' ||
          key === 'innerComments'
        ) {
          continue;
        }
        const val = node[key];
        if (Array.isArray(val)) {
          for (const item of val) {
            walkAny(item, cb);
          }
        } else if (val && typeof val === 'object' && typeof val.type === 'string') {
          walkAny(val, cb);
        }
      }
    };

    const imports: AstImportNode[] = [];
    const functions: AstFunctionNode[] = [];
    const callSites: AstCallSite[] = [];
    const issues: AstIssueCandidate[] = [];

    let totalCyclomatic = 1;
    let totalCognitive = 0;
    let hasAuditSignals = false;
    let hasCryptoSignals = false;
    let hasWeakCryptoSignals = false;
    let hasPreparedStatementSignals = false;

    const usedIdentifiers = new Set<string>();
    const importedIdentMap = new Map<string, { lineNumber: number; sourcePath: string }>();

    // Collect identifiers used outside import declarations for unused-import AST check
    walkAny(ast.program, (node) => {
      if (node.type === 'ImportDeclaration') return false;
      if (node.type === 'Identifier' && typeof node.name === 'string') {
        usedIdentifiers.add(node.name);
      } else if (node.type === 'JSXIdentifier' && typeof node.name === 'string') {
        usedIdentifiers.add(node.name);
      }
    });

    const extractIdentifiersFromExpr = (expr: any): string[] => {
      const ids: string[] = [];
      walkAny(expr, (n) => {
        if (n.type === 'Identifier' && typeof n.name === 'string') {
          ids.push(n.name);
        }
      });
      return Array.from(new Set(ids));
    };

    const getCalleeText = (expr: any): string => {
      if (!expr || typeof expr !== 'object') return '';
      if (expr.type === 'Identifier') return expr.name || '';
      if (expr.type === 'ThisExpression') return 'this';
      if (expr.type === 'Super') return 'super';
      if (expr.type === 'MemberExpression' || expr.type === 'OptionalMemberExpression') {
        const obj = getCalleeText(expr.object);
        const prop =
          expr.property?.name || expr.property?.value || getSourceText(expr.property);
        return obj ? `${obj}.${prop}` : String(prop || '');
      }
      return getSourceText(expr);
    };

    const extractParamName = (p: any): string => {
      if (!p || typeof p !== 'object') return '';
      if (p.type === 'Identifier') return p.name || '';
      if (p.type === 'AssignmentPattern') return extractParamName(p.left);
      if (p.type === 'RestElement') return extractParamName(p.argument);
      if (p.type === 'TSParameterProperty') return extractParamName(p.parameter);
      return getSourceText(p);
    };

    const containsSqlConcat = (node: any): boolean => {
      if (!node || typeof node !== 'object') return false;
      if (node.type === 'BinaryExpression' && node.operator === '+') {
        const text = getSourceText(node);
        let hasSqlLiteral = false;
        walkAny(node, (n) => {
          if (n.type === 'StringLiteral' && SQL_KEYWORD_PATTERN.test(n.value || '')) {
            hasSqlLiteral = true;
          } else if (
            n.type === 'TemplateLiteral' &&
            Array.isArray(n.expressions) &&
            n.expressions.length === 0
          ) {
            const raw = n.quasis?.map((q: any) => q.value?.raw || '').join('') || '';
            if (SQL_KEYWORD_PATTERN.test(raw)) hasSqlLiteral = true;
          }
        });
        return hasSqlLiteral && extractIdentifiersFromExpr(node).length > 0 && !text.includes('?');
      }
      if (node.type === 'TemplateLiteral' && Array.isArray(node.expressions) && node.expressions.length > 0) {
        const hasSqlQuasi = (node.quasis || []).some((q: any) =>
          SQL_KEYWORD_PATTERN.test(q.value?.cooked || q.value?.raw || '')
        );
        return hasSqlQuasi;
      }
      return false;
    };

    const FN_NODE_TYPES = new Set([
      'FunctionDeclaration',
      'FunctionExpression',
      'ArrowFunctionExpression',
      'ClassMethod',
      'ObjectMethod',
    ]);

    const COMPLEXITY_NODE_TYPES = new Set([
      'IfStatement',
      'ConditionalExpression',
      'ForStatement',
      'ForOfStatement',
      'ForInStatement',
      'WhileStatement',
      'DoWhileStatement',
      'CatchClause',
    ]);

    const walkFunctionBody = (
      fnNode: any,
      fnName: string,
      isExported: boolean
    ): AstFunctionNode => {
      const startLine = getLine(fnNode);
      const endLine = getEndLine(fnNode);
      const params = ((fnNode.params || []) as any[])
        .map(extractParamName)
        .filter((p) => p.length > 0);
      let fnCyclomatic = 1;
      let fnCognitive = 0;
      const callsMade: AstCallSite[] = [];
      const variableBindings: AstFunctionNode['variableBindings'] = [];
      const returnValues: string[] = [];

      const visit = (node: any, nesting: number, inTry: boolean): void => {
        if (!node || typeof node !== 'object' || typeof node.type !== 'string') return;

        // Complexity calculation strictly from AST control-flow nodes
        if (
          COMPLEXITY_NODE_TYPES.has(node.type) ||
          (node.type === 'SwitchCase' && node.test !== null)
        ) {
          fnCyclomatic += 1;
          fnCognitive += 1 + nesting;
        } else if (
          node.type === 'LogicalExpression' &&
          (node.operator === '&&' || node.operator === '||' || node.operator === '??')
        ) {
          fnCyclomatic += 1;
          fnCognitive += 1;
        }

        // Dead / Unreachable code after return/throw/break/continue inside BlockStatement
        if (node.type === 'BlockStatement' && Array.isArray(node.body)) {
          let terminated = false;
          for (const stmt of node.body) {
            if (terminated) {
              if (stmt.type === 'FunctionDeclaration' || stmt.type === 'EmptyStatement') continue;
              const lineNo = getLine(stmt);
              issues.push({
                ruleId: 'ts:S1763',
                title: 'Código inalcançável (Dead Code) detectado via AST',
                description:
                  'Instrução declarada após comando de término incondicional (return/throw/break/continue).',
                category: 'CODE_QUALITY',
                severity: 'MEDIUM',
                cwe: 'CWE-561',
                filePath,
                lineNumber: lineNo,
                endLineNumber: getEndLine(stmt),
                snippet: getSnippet(lineNo),
                remediation:
                  'Remover código morto após retorno ou lançar exceção apenas no fluxo condicional correto.',
                detectionMethod: 'AST_ANALYSIS',
                confidence: 'HIGH',
                effortMinutes: 5,
              });
              break;
            }
            if (
              stmt.type === 'ReturnStatement' ||
              stmt.type === 'ThrowStatement' ||
              stmt.type === 'BreakStatement' ||
              stmt.type === 'ContinueStatement'
            ) {
              terminated = true;
            }
          }
        }

        // Empty Catch Clause
        if (node.type === 'CatchClause' && Array.isArray(node.body?.body) && node.body.body.length === 0) {
          const lineNo = getLine(node);
          issues.push({
            ruleId: 'ts:S2486',
            title: 'Bloco catch vazio silencia exceções críticas',
            description:
              'Exceções capturadas sem registro, tratamento ou relançamento ocultam falhas de segurança e confiabilidade.',
            category: 'CODE_QUALITY',
            severity: 'HIGH',
            cwe: 'CWE-390',
            filePath,
            lineNumber: lineNo,
            endLineNumber: getEndLine(node),
            snippet: getSnippet(lineNo),
            remediation: 'Registrar erro de forma estruturada ou propagar exceção controlada.',
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 10,
          });
        }

        // Explicit `any` keyword
        if (node.type === 'TSAnyKeyword' && !filePath.toLowerCase().includes('test')) {
          const lineNo = getLine(node);
          issues.push({
            ruleId: 'ts:S4204',
            title: 'Uso de tipo explícito "any" enfraquece segurança de tipos',
            description:
              'Uso de any desabilita verificação estática do compilador TypeScript na fronteira de dados.',
            category: 'CODE_QUALITY',
            severity: 'LOW',
            cwe: 'CWE-710',
            filePath,
            lineNumber: lineNo,
            endLineNumber: lineNo,
            snippet: getSnippet(lineNo),
            remediation: 'Substituir any por interface tipada ou unknown com type guard.',
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 5,
          });
        }

        // Variable declarations: SQL concat, Secrets, Taint bindings
        if (node.type === 'VariableDeclarator' && node.init && node.id?.type === 'Identifier') {
          const varName: string = node.id.name;
          const lineNo = getLine(node);
          const exprText = getSourceText(node.init);
          const deps = extractIdentifiersFromExpr(node.init);

          let isSanitized = false;
          let sanitizerName: string | undefined;
          let sanitizerContext:
            | 'NUMERIC'
            | 'URL_ENCODE'
            | 'HTML_ESCAPE'
            | 'PATH_BASENAME'
            | 'CRYPTO_KDF'
            | 'SQL_PREPARED'
            | 'GENERIC_SCHEMA'
            | undefined;
          if (node.init.type === 'CallExpression' || node.init.type === 'OptionalCallExpression') {
            const calleeTxt = getCalleeText(node.init.callee);
            const shortCallee = calleeTxt.split('.').pop() || calleeTxt;
            const ctx = classifySanitizerContext(calleeTxt, shortCallee);
            if (ctx) {
              isSanitized = true;
              sanitizerName = calleeTxt;
              sanitizerContext = ctx;
            }
          }

          variableBindings.push({
            varName,
            lineNumber: lineNo,
            expressionText: exprText,
            dependencies: deps,
            isSanitized,
            sanitizerName,
            sanitizerContext,
          });

          // Hardcoded high-entropy secret literal in AST
          if (
            node.init.type === 'StringLiteral' &&
            SECRET_IDENTIFIER_HINT.test(varName) &&
            typeof node.init.value === 'string' &&
            node.init.value.length >= 12 &&
            !PLACEHOLDER_SECRET_HINT.test(node.init.value)
          ) {
            const ent = shannonEntropy(node.init.value);
            if (ent >= 2.8) {
              issues.push({
                ruleId: 'ts:S6418',
                title: `Credencial/Chave hardcoded detectada na variável "${varName}"`,
                description: `Literal string de alta entropia (${ent.toFixed(2)} bits/char) atribuído diretamente em código-fonte.`,
                category: 'SECRETS',
                severity: 'BLOCKER',
                cwe: 'CWE-798',
                filePath,
                lineNumber: lineNo,
                endLineNumber: lineNo,
                snippet: getSnippet(lineNo),
                remediation:
                  'Remover segredo do código-fonte e injetar via vault/KMS ou variável de ambiente.',
                detectionMethod: 'AST_ANALYSIS',
                confidence: 'HIGH',
                effortMinutes: 25,
              });
            }
          }

          // Prepared statement signal
          const initStringVal =
            node.init.type === 'StringLiteral'
              ? node.init.value
              : node.init.type === 'TemplateLiteral' && node.init.expressions?.length === 0
                ? node.init.quasis?.[0]?.value?.cooked || node.init.quasis?.[0]?.value?.raw || ''
                : '';
          if (
            initStringVal &&
            SQL_KEYWORD_PATTERN.test(initStringVal) &&
            (initStringVal.includes('?') || /\$\d+/.test(initStringVal))
          ) {
            hasPreparedStatementSignals = true;
          }

          // Dynamic SQL construction via binary + or template interpolation
          if (containsSqlConcat(node.init)) {
            issues.push({
              ruleId: 'ts:S3649',
              title: 'Consulta SQL dinâmica construída por concatenação/interpolação',
              description:
                'String SQL construída dinamicamente com identificadores sem uso de placeholders parametrizados.',
              category: 'SAST',
              severity: 'CRITICAL',
              cwe: 'CWE-89',
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: getSnippet(lineNo),
              remediation: 'Utilizar Prepared Statements com marcadores parametrizados (? ou $1).',
              detectionMethod: 'AST_ANALYSIS',
              confidence: 'HIGH',
              effortMinutes: 30,
            });
          }
        }

        // Return statements
        if (node.type === 'ReturnStatement' && node.argument) {
          returnValues.push(...extractIdentifiersFromExpr(node.argument));
        }

        // Call expressions: sinks, crypto, audit signals, call-graph
        if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression') {
          const lineNo = getLine(node);
          const callee = getCalleeText(node.callee);
          const calleeBase = callee.split('.').pop() || callee;
          const args = Array.isArray(node.arguments) ? node.arguments : [];
          const argsText: string[] = args.map((a: any) => getSourceText(a));
          const argIdentifiers: string[] = Array.from(
            new Set<string>(args.flatMap((a: any) => extractIdentifiersFromExpr(a)))
          );

          const callSite: AstCallSite = {
            callee,
            calleeBase,
            filePath,
            lineNumber: lineNo,
            argsText,
            argIdentifiers,
            snippet: getSnippet(lineNo),
            enclosingFunction: fnName,
            inTryBlock: inTry,
          };
          callsMade.push(callSite);
          callSites.push(callSite);

          const firstArgStr = args[0]?.type === 'StringLiteral' ? String(args[0].value || '') : '';

          // Crypto detection via AST
          if (/aes-256-gcm|pbkdf2Sync|argon2|scryptSync/i.test(`${callee} ${firstArgStr}`)) {
            hasCryptoSignals = true;
          }
          if (/append.*audit|auditLog|sha256/i.test(`${callee} ${firstArgStr}`)) {
            hasAuditSignals = true;
          }

          // Weak hash / cipher
          if (
            (/createHash/i.test(callee) && /^(md5|sha1)$/i.test(firstArgStr)) ||
            /CryptoJS\.(MD5|SHA1)/i.test(callee)
          ) {
            hasWeakCryptoSignals = true;
            issues.push({
              ruleId: 'ts:S4790',
              title: `Algoritmo criptográfico fraco (${firstArgStr || calleeBase}) detectado via AST`,
              description:
                'MD5/SHA-1 possuem colisões conhecidas e são inadequados para senhas ou integridade crítica.',
              category: 'SAST',
              severity: 'CRITICAL',
              cwe: 'CWE-328',
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: getSnippet(lineNo),
              remediation:
                'Migrar para PBKDF2-HMAC-SHA512 (>= 600.000 iterações), Argon2id ou SHA-256/512.',
              detectionMethod: 'AST_ANALYSIS',
              confidence: 'HIGH',
              effortMinutes: 20,
            });
          }

          // Insecure Math.random() in non-test code
          if (callee === 'Math.random' && !filePath.toLowerCase().includes('test')) {
            issues.push({
              ruleId: 'ts:S2245',
              title: 'Gerador pseudoaleatório previsível Math.random() em lógica de aplicação',
              description:
                'Math.random() não é criptograficamente seguro (CSPRNG) e não deve gerar tokens, nonces ou sais.',
              category: 'SAST',
              severity: 'HIGH',
              cwe: 'CWE-338',
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: getSnippet(lineNo),
              remediation: 'Substituir por crypto.randomBytes() ou crypto.randomUUID().',
              detectionMethod: 'AST_ANALYSIS',
              confidence: 'HIGH',
              effortMinutes: 15,
            });
          }

          // Command execution / eval
          if (calleeBase === 'execSync' || calleeBase === 'exec' || callee === 'eval') {
            const hasDynamicArg = args.some(
              (a: any) =>
                (a.type === 'TemplateLiteral' && a.expressions?.length > 0) ||
                a.type === 'BinaryExpression' ||
                a.type === 'Identifier' ||
                a.type === 'MemberExpression'
            );
            if (hasDynamicArg) {
              issues.push({
                ruleId: 'ts:S2076',
                title: `Execução de comando/código dinâmica em ${callee}`,
                description:
                  'Invocação de shell ou eval com argumento dinâmico permite injeção de comandos arbitrários.',
                category: 'SAST',
                severity: 'BLOCKER',
                cwe: 'CWE-78',
                filePath,
                lineNumber: lineNo,
                endLineNumber: lineNo,
                snippet: getSnippet(lineNo),
                remediation:
                  'Substituir por execFile/spawn com shell: false, lista fixa de argumentos e validação estrita.',
                detectionMethod: 'AST_ANALYSIS',
                confidence: 'HIGH',
                effortMinutes: 30,
              });
            }
          }

          // Direct SQL execution with unsafe argument
          if (/^(query|execute|raw|exec)$/i.test(calleeBase) && args[0]) {
            if (containsSqlConcat(args[0])) {
              issues.push({
                ruleId: 'ts:S3649',
                title: 'Execução SQL com string concatenada/interpolada',
                description: 'Consulta passada diretamente a executor SQL com interpolação de expressão.',
                category: 'SAST',
                severity: 'BLOCKER',
                cwe: 'CWE-89',
                filePath,
                lineNumber: lineNo,
                endLineNumber: lineNo,
                snippet: getSnippet(lineNo),
                remediation: 'Usar placeholders parametrizados e binding seguro.',
                detectionMethod: 'AST_ANALYSIS',
                confidence: 'HIGH',
                effortMinutes: 30,
              });
            }
          }
        }

        // new Function(...)
        if (node.type === 'NewExpression' && getCalleeText(node.callee) === 'Function') {
          const lineNo = getLine(node);
          issues.push({
            ruleId: 'ts:S1523',
            title: 'Construção dinâmica via new Function() detectada',
            description:
              'Avaliação dinâmica de código equivale a eval() e expõe superfície de Code Injection.',
            category: 'SAST',
            severity: 'CRITICAL',
            cwe: 'CWE-95',
            filePath,
            lineNumber: lineNo,
            endLineNumber: lineNo,
            snippet: getSnippet(lineNo),
            remediation: 'Substituir por funções estáticas tipadas ou tabela de despacho segura.',
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 25,
          });
        }

        const nextNesting =
          node.type === 'IfStatement' ||
          node.type === 'ForStatement' ||
          node.type === 'ForOfStatement' ||
          node.type === 'ForInStatement' ||
          node.type === 'WhileStatement' ||
          node.type === 'DoWhileStatement' ||
          node.type === 'TryStatement'
            ? nesting + 1
            : nesting;
        const nextInTry = inTry || node.type === 'TryStatement';

        if (node !== fnNode && FN_NODE_TYPES.has(node.type)) {
          return; // Handled separately by outer AST traversal
        }

        for (const key of Object.keys(node)) {
          if (
            key === 'loc' ||
            key === 'start' ||
            key === 'end' ||
            key === 'extra' ||
            key === 'leadingComments' ||
            key === 'trailingComments' ||
            key === 'innerComments'
          ) {
            continue;
          }
          const val = node[key];
          if (Array.isArray(val)) {
            for (const item of val) {
              if (item && typeof item === 'object' && typeof item.type === 'string') {
                visit(item, nextNesting, nextInTry);
              }
            }
          } else if (val && typeof val === 'object' && typeof val.type === 'string') {
            visit(val, nextNesting, nextInTry);
          }
        }
      };

      if (fnNode.body) {
        visit(fnNode.body, 0, false);
      }

      return {
        name: fnName,
        filePath,
        startLine,
        endLine,
        params,
        cyclomaticComplexity: fnCyclomatic,
        cognitiveComplexity: fnCognitive,
        isExported,
        callsMade,
        returnValues: Array.from(new Set<string>(returnValues)),
        variableBindings,
      };
    };

    const traverseTop = (node: any, parentIsExport: boolean): void => {
      if (!node || typeof node !== 'object' || typeof node.type !== 'string') return;

      if (node.type === 'ImportDeclaration' && node.source?.type === 'StringLiteral') {
        const lineNumber = getLine(node);
        const sourcePath = String(node.source.value || '');
        const importedSymbols: AstImportNode['importedSymbols'] = [];
        const isTypeOnlyDecl = node.importKind === 'type' || node.importKind === 'typeof';

        for (const spec of node.specifiers || []) {
          const sym = spec.local?.name;
          if (!sym) continue;
          const isTypeOnlySpec = isTypeOnlyDecl || spec.importKind === 'type' || spec.importKind === 'typeof';
          const usedInBody = isTypeOnlySpec || usedIdentifiers.has(sym);
          importedSymbols.push({ name: sym, lineNumber, usedInBody });
          importedIdentMap.set(sym, { lineNumber, sourcePath });
        }

        imports.push({ sourcePath, importedSymbols, lineNumber });

        if (!isTypeOnlyDecl) {
          for (const sym of importedSymbols) {
            if (!sym.usedInBody) {
              issues.push({
                ruleId: 'ts:S1128',
                title: `Import não utilizado: "${sym.name}"`,
                description: `Símbolo "${sym.name}" importado de "${sourcePath}" não é referenciado no escopo do módulo.`,
                category: 'CODE_QUALITY',
                severity: 'LOW',
                cwe: 'CWE-561',
                filePath,
                lineNumber: sym.lineNumber,
                endLineNumber: sym.lineNumber,
                snippet: getSnippet(sym.lineNumber),
                remediation: `Remover importação não utilizada "${sym.name}".`,
                detectionMethod: 'AST_ANALYSIS',
                confidence: 'HIGH',
                effortMinutes: 2,
              });
            }
          }
        }
      }

      if (node.type === 'FunctionDeclaration') {
        const name = node.id?.name || '<anonymous>';
        const fnInfo = walkFunctionBody(node, name, parentIsExport);
        functions.push(fnInfo);
        totalCyclomatic += Math.max(0, fnInfo.cyclomaticComplexity - 1);
        totalCognitive += fnInfo.cognitiveComplexity;
      } else if (node.type === 'ClassMethod' || node.type === 'ObjectMethod') {
        const name = node.key?.name || node.key?.value || '<method>';
        const isExported = node.accessibility !== 'private';
        const fnInfo = walkFunctionBody(node, String(name), isExported);
        functions.push(fnInfo);
        totalCyclomatic += Math.max(0, fnInfo.cyclomaticComplexity - 1);
        totalCognitive += fnInfo.cognitiveComplexity;
      } else if (node.type === 'VariableDeclaration') {
        for (const decl of node.declarations || []) {
          if (
            decl.init &&
            (decl.init.type === 'ArrowFunctionExpression' || decl.init.type === 'FunctionExpression')
          ) {
            const name = decl.id?.type === 'Identifier' ? decl.id.name : getSourceText(decl.id) || '<anonymous>';
            const fnInfo = walkFunctionBody(decl.init, name, parentIsExport);
            functions.push(fnInfo);
            totalCyclomatic += Math.max(0, fnInfo.cyclomaticComplexity - 1);
            totalCognitive += fnInfo.cognitiveComplexity;
          } else if (decl.init && decl.id?.type === 'Identifier') {
            const lineNo = getLine(decl);
            const varName: string = decl.id.name;
            if (
              decl.init.type === 'StringLiteral' &&
              SECRET_IDENTIFIER_HINT.test(varName) &&
              typeof decl.init.value === 'string' &&
              decl.init.value.length >= 12 &&
              !PLACEHOLDER_SECRET_HINT.test(decl.init.value)
            ) {
              const ent = shannonEntropy(decl.init.value);
              if (ent >= 2.8) {
                issues.push({
                  ruleId: 'ts:S6418',
                  title: `Credencial/Chave hardcoded detectada em "${varName}"`,
                  description: `Literal string de alta entropia (${ent.toFixed(2)} bits/char) declarado no escopo de módulo.`,
                  category: 'SECRETS',
                  severity: 'BLOCKER',
                  cwe: 'CWE-798',
                  filePath,
                  lineNumber: lineNo,
                  endLineNumber: lineNo,
                  snippet: getSnippet(lineNo),
                  remediation: 'Substituir por variável de ambiente protegida ou cofre KMS.',
                  detectionMethod: 'AST_ANALYSIS',
                  confidence: 'HIGH',
                  effortMinutes: 25,
                });
              }
            }
          }
        }
      }

      const childExported =
        node.type === 'ExportNamedDeclaration' || node.type === 'ExportDefaultDeclaration';

      for (const key of Object.keys(node)) {
        if (
          key === 'loc' ||
          key === 'start' ||
          key === 'end' ||
          key === 'extra' ||
          key === 'leadingComments' ||
          key === 'trailingComments' ||
          key === 'innerComments'
        ) {
          continue;
        }
        const val = node[key];
        if (Array.isArray(val)) {
          for (const item of val) {
            if (item && typeof item === 'object' && typeof item.type === 'string') {
              traverseTop(item, childExported);
            }
          }
        } else if (val && typeof val === 'object' && typeof val.type === 'string') {
          traverseTop(val, childExported);
        }
      }
    };

    traverseTop(ast.program, false);

    return {
      filePath,
      language,
      astParsed: true,
      parserKind: 'BABEL_AST',
      errorCount: Array.isArray(ast?.errors) ? ast.errors.length : 0,
      parserEngine: '@babel/parser-ts-js-ast',
      loc: lines.filter((l) => l.trim().length > 0 && !l.trim().startsWith('//')).length,
      cyclomaticComplexity: Math.max(1, totalCyclomatic),
      cognitiveComplexity: totalCognitive,
      imports,
      functions,
      callSites,
      issues,
      hasAuditSignals,
      hasCryptoSignals,
      hasWeakCryptoSignals,
      hasPreparedStatementSignals,
    };
  }

  private static parsePythonStructuralAst(filePath: string, content: string): AstParseResult {
    const pyKeywords = new Set([
      'def', 'class', 'if', 'elif', 'else', 'for', 'while', 'try', 'except', 'finally',
      'import', 'from', 'as', 'return', 'raise', 'pass', 'and', 'or', 'with', 'lambda',
    ]);
    const tokens = tokenizeGenericSource(content, pyKeywords, true);
    const lines = content.split(/\r?\n/);
    const imports: AstImportNode[] = [];
    const functions: AstFunctionNode[] = [];
    const callSites: AstCallSite[] = [];
    const issues: AstIssueCandidate[] = [];

    let cyclomatic = 1;
    let cognitive = 0;
    let hasWeakCrypto = false;
    let hasCrypto = false;
    let hasPrepared = false;
    let hasAudit = false;
    let currentFn = '<module>';

    for (let idx = 0; idx < tokens.length; idx++) {
      const tok = tokens[idx]!;
      const next = tokens[idx + 1];
      const next2 = tokens[idx + 2];

      if (tok.type === 'COMMENT') continue;

      if (tok.type === 'KEYWORD' && (tok.value === 'import' || tok.value === 'from')) {
        if (next && next.type === 'IDENT') {
          imports.push({
            sourcePath: next.value,
            importedSymbols: [{ name: next.value, lineNumber: tok.line, usedInBody: true }],
            lineNumber: tok.line,
          });
        }
      }

      if (tok.type === 'KEYWORD' && tok.value === 'def' && next?.type === 'IDENT') {
        currentFn = next.value;
        const params: string[] = [];
        let j = idx + 2;
        if (tokens[j]?.value === '(') {
          j += 1;
          while (j < tokens.length && tokens[j]!.value !== ')') {
            if (tokens[j]!.type === 'IDENT' && tokens[j]!.value !== 'self') {
              params.push(tokens[j]!.value);
            }
            j += 1;
          }
        }
        functions.push({
          name: currentFn,
          filePath,
          startLine: tok.line,
          endLine: tok.line,
          params,
          cyclomaticComplexity: 1,
          cognitiveComplexity: 0,
          isExported: !currentFn.startsWith('_'),
          callsMade: [],
          returnValues: [],
          variableBindings: [],
        });
      }

      if (tok.type === 'KEYWORD' && ['if', 'elif', 'for', 'while', 'except', 'and', 'or'].includes(tok.value)) {
        cyclomatic += 1;
        cognitive += 1;
      }

      // except ... : pass
      if (tok.type === 'KEYWORD' && tok.value === 'except') {
        let k = idx + 1;
        while (k < tokens.length && tokens[k]!.value !== ':' && tokens[k]!.line === tok.line) k++;
        if (tokens[k]?.value === ':' && tokens[k + 1]?.value === 'pass') {
          issues.push({
            ruleId: 'py:S108',
            title: 'Bloco except com pass silencia exceções em Python',
            description: 'Captura genérica com pass oculta erros operacionais e de segurança.',
            category: 'CODE_QUALITY',
            severity: 'HIGH',
            cwe: 'CWE-390',
            filePath,
            lineNumber: tok.line,
            endLineNumber: tok.line + 1,
            snippet: (lines[tok.line - 1] || '').trim(),
            remediation: 'Registrar exceção via logging.exception ou relançar erro específico.',
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 10,
          });
        }
      }

      // Secrets in variable assignment: ident = "secret"
      if (tok.type === 'IDENT' && next?.value === '=' && next2?.type === 'STRING') {
        const raw = next2.value.slice(1, -1);
        if (SECRET_IDENTIFIER_HINT.test(tok.value) && raw.length >= 12 && !PLACEHOLDER_SECRET_HINT.test(raw)) {
          if (shannonEntropy(raw) >= 2.8) {
            issues.push({
              ruleId: 'py:S6418',
              title: `Segredo hardcoded em Python (${tok.value})`,
              description: 'Chave ou senha atribuída como string literal em módulo Python.',
              category: 'SECRETS',
              severity: 'BLOCKER',
              cwe: 'CWE-798',
              filePath,
              lineNumber: tok.line,
              endLineNumber: tok.line,
              snippet: (lines[tok.line - 1] || '').trim(),
              remediation: 'Ler segredo via os.environ ou gerenciador de segredos.',
              detectionMethod: 'AST_ANALYSIS',
              confidence: 'HIGH',
              effortMinutes: 25,
            });
          }
        }
      }

      // Call expressions: name(...) or obj.name(...)
      if (tok.type === 'IDENT' && next?.value === '(') {
        const prevIdent = tokens[idx - 1]?.value === '.' ? `${tokens[idx - 2]?.value || ''}.${tok.value}` : tok.value;
        const callArgs: string[] = [];
        let k = idx + 2;
        let depth = 1;
        while (k < tokens.length && depth > 0) {
          if (tokens[k]!.value === '(') depth += 1;
          else if (tokens[k]!.value === ')') depth -= 1;
          else if (tokens[k]!.type === 'IDENT' || tokens[k]!.type === 'STRING') {
            callArgs.push(tokens[k]!.value);
          }
          k += 1;
        }

        const site: AstCallSite = {
          callee: prevIdent,
          calleeBase: tok.value,
          filePath,
          lineNumber: tok.line,
          argsText: callArgs,
          argIdentifiers: callArgs.filter((a) => !a.startsWith('"') && !a.startsWith("'")),
          snippet: (lines[tok.line - 1] || '').trim(),
          enclosingFunction: currentFn,
          inTryBlock: false,
        };
        callSites.push(site);

        if (prevIdent === 'hashlib.md5' || prevIdent === 'hashlib.sha1') {
          hasWeakCrypto = true;
          issues.push({
            ruleId: 'py:B324',
            title: `Hash fraco ${prevIdent}() detectado em Python`,
            description: 'MD5/SHA-1 são vulneráveis a colisões e quebra rápida.',
            category: 'SAST',
            severity: 'CRITICAL',
            cwe: 'CWE-328',
            filePath,
            lineNumber: tok.line,
            endLineNumber: tok.line,
            snippet: site.snippet,
            remediation: 'Usar hashlib.sha256(), hashlib.pbkdf2_hmac() ou argon2.',
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 15,
          });
        }
        if (tok.value === 'eval' || tok.value === 'exec' || prevIdent === 'os.system' || prevIdent === 'pickle.loads') {
          const pyCwe =
            prevIdent === 'pickle.loads'
              ? 'CWE-502'
              : tok.value === 'eval' || tok.value === 'exec'
                ? 'CWE-95'
                : 'CWE-78';
          issues.push({
            ruleId: 'py:B307',
            title: `Chamada de alto risco ${prevIdent}() em Python`,
            description: 'Uso de eval/exec/os.system/pickle.loads permite execução arbitrária de código/comandos.',
            category: 'SAST',
            severity: 'BLOCKER',
            cwe: pyCwe,
            filePath,
            lineNumber: tok.line,
            endLineNumber: tok.line,
            snippet: site.snippet,
            remediation: 'Usar subprocess.run(..., shell=False) ou json.loads/ast.literal_eval.',
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 25,
          });
        }
        if (/^subprocess\.(run|Popen|call|check_output)$/i.test(prevIdent) && /shell\s*=\s*True/i.test(site.snippet)) {
          issues.push({
            ruleId: 'py:B602',
            title: `Invocação ${prevIdent}() com shell=True expõe Command Injection`,
            description: 'Execução via shell=True com string formatada/dinâmica permite injeção de comandos no SO.',
            category: 'SAST',
            severity: 'BLOCKER',
            cwe: 'CWE-78',
            filePath,
            lineNumber: tok.line,
            endLineNumber: tok.line,
            snippet: site.snippet,
            remediation: 'Passar lista explícita de argumentos com shell=False.',
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 25,
          });
        }
        if (tok.value === 'execute' && (site.snippet.includes('f"') || site.snippet.includes('+'))) {
          issues.push({
            ruleId: 'py:B608',
            title: 'SQL construído com f-string ou concatenação em cursor.execute()',
            description: 'Interpolação direta em query SQL expõe o sistema a SQL Injection.',
            category: 'SAST',
            severity: 'BLOCKER',
            cwe: 'CWE-89',
            filePath,
            lineNumber: tok.line,
            endLineNumber: tok.line,
            snippet: site.snippet,
            remediation: 'Usar parâmetros vinculados cursor.execute(sql, (param,)).',
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 25,
          });
        }
        if (/pbkdf2_hmac|AES|Fernet/i.test(prevIdent)) hasCrypto = true;
        if (tok.value === 'execute' && (site.snippet.includes('?') || site.snippet.includes('%s'))) hasPrepared = true;
        if (/audit/i.test(prevIdent)) hasAudit = true;

        const fnObj = functions.find((f) => f.name === currentFn);
        if (fnObj) fnObj.callsMade.push(site);
      }
    }

    return {
      filePath,
      language: 'Python',
      astParsed: true,
      parserKind: 'STRUCTURAL_PARSER',
      errorCount: 0,
      parserEngine: 'winhood-python-structural-ast-v1',
      loc: lines.filter((l) => l.trim().length > 0 && !l.trim().startsWith('#')).length,
      cyclomaticComplexity: cyclomatic,
      cognitiveComplexity: cognitive,
      imports,
      functions,
      callSites,
      issues,
      hasAuditSignals: hasAudit,
      hasCryptoSignals: hasCrypto,
      hasWeakCryptoSignals: hasWeakCrypto,
      hasPreparedStatementSignals: hasPrepared,
    };
  }

  private static parseBraceLanguageStructuralAst(
    filePath: string,
    content: string,
    language: 'Java' | 'C#' | 'Go' | 'Rust'
  ): AstParseResult {
    const keywords = new Set([
      'import', 'using', 'use', 'package', 'namespace', 'class', 'struct', 'interface',
      'public', 'private', 'protected', 'func', 'fn', 'void', 'if', 'else', 'for',
      'while', 'switch', 'case', 'try', 'catch', 'match', 'return', 'new', 'unsafe',
    ]);
    const tokens = tokenizeGenericSource(content, keywords, false);
    const lines = content.split(/\r?\n/);
    const imports: AstImportNode[] = [];
    const functions: AstFunctionNode[] = [];
    const callSites: AstCallSite[] = [];
    const issues: AstIssueCandidate[] = [];

    let cyclomatic = 1;
    let cognitive = 0;
    let nesting = 0;
    let hasWeakCrypto = false;
    let hasCrypto = false;
    let hasPrepared = false;

    for (let idx = 0; idx < tokens.length; idx++) {
      const tok = tokens[idx]!;
      if (tok.type === 'COMMENT') continue;

      if (tok.value === '{') nesting += 1;
      else if (tok.value === '}') nesting = Math.max(0, nesting - 1);

      if (tok.type === 'KEYWORD' && ['if', 'for', 'while', 'case', 'catch', 'match'].includes(tok.value)) {
        cyclomatic += 1;
        cognitive += 1 + Math.max(0, nesting - 1);
      }

      if (tok.type === 'KEYWORD' && (tok.value === 'import' || tok.value === 'using' || tok.value === 'use')) {
        const next = tokens[idx + 1];
        if (next && (next.type === 'IDENT' || next.type === 'STRING')) {
          imports.push({
            sourcePath: next.value.replace(/^"|"$/g, ''),
            importedSymbols: [{ name: next.value, lineNumber: tok.line, usedInBody: true }],
            lineNumber: tok.line,
          });
        }
      }

      // Empty catch block in Java / C#
      if (tok.type === 'KEYWORD' && tok.value === 'catch') {
        let k = idx + 1;
        while (k < tokens.length && tokens[k]!.value !== '{') k++;
        if (tokens[k]?.value === '{' && tokens[k + 1]?.value === '}') {
          issues.push({
            ruleId: `${language.toLowerCase()}:S2486`,
            title: `Bloco catch vazio em ${language}`,
            description: 'Captura de exceção sem tratamento nem log mascara falhas em tempo de execução.',
            category: 'CODE_QUALITY',
            severity: 'HIGH',
            cwe: 'CWE-390',
            filePath,
            lineNumber: tok.line,
            endLineNumber: tokens[k + 1]!.line,
            snippet: (lines[tok.line - 1] || '').trim(),
            remediation: 'Registrar erro ou encapsular em exceção de domínio.',
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 10,
          });
        }
      }

      // Unsafe block in Rust / C#
      if (tok.type === 'KEYWORD' && tok.value === 'unsafe' && (language === 'Rust' || language === 'C#')) {
        issues.push({
          ruleId: `${language.toLowerCase()}:UNSAFE`,
          title: `Bloco unsafe em ${language}`,
          description: 'Uso de bloco unsafe contorna garantias de segurança de memória do compilador.',
          category: 'SAST',
          severity: 'MEDIUM',
          cwe: 'CWE-119',
          filePath,
          lineNumber: tok.line,
          endLineNumber: tok.line,
          snippet: (lines[tok.line - 1] || '').trim(),
          remediation: 'Isolar FFI/unsafe e justificar invariantes de memória.',
          detectionMethod: 'AST_ANALYSIS',
          confidence: 'HIGH',
          effortMinutes: 20,
        });
      }

      // Function declarations in Go/Rust
      if ((tok.value === 'func' || tok.value === 'fn') && tokens[idx + 1]?.type === 'IDENT') {
        functions.push({
          name: tokens[idx + 1]!.value,
          filePath,
          startLine: tok.line,
          endLine: tok.line,
          params: [],
          cyclomaticComplexity: 1,
          cognitiveComplexity: 0,
          isExported: true,
          callsMade: [],
          returnValues: [],
          variableBindings: [],
        });
      }

      // Call expression detection
      if (tok.type === 'IDENT' && tokens[idx + 1]?.value === '(') {
        const snippet = (lines[tok.line - 1] || '').trim();
        const callee = tokens[idx - 1]?.value === '.' ? `${tokens[idx - 2]?.value || ''}.${tok.value}` : tok.value;
        callSites.push({
          callee,
          calleeBase: tok.value,
          filePath,
          lineNumber: tok.line,
          argsText: [],
          argIdentifiers: [],
          snippet,
          enclosingFunction: '<block>',
          inTryBlock: false,
        });

        if (/^(executeQuery|ExecuteReader|Exec|Raw)$/i.test(tok.value) && snippet.includes('+')) {
          issues.push({
            ruleId: `${language.toLowerCase()}:S2077`,
            title: `SQL concatenado em ${callee}() (${language})`,
            description: 'Consulta SQL construída por concatenação com operador "+" em chamada de banco.',
            category: 'SAST',
            severity: 'BLOCKER',
            cwe: 'CWE-89',
            filePath,
            lineNumber: tok.line,
            endLineNumber: tok.line,
            snippet,
            remediation: 'Utilizar PreparedStatement / SqlParameter / query parametrizada.',
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 30,
          });
        }
        if (/PreparedStatement|SqlParameter/i.test(snippet)) hasPrepared = true;
        if (/MD5|SHA1/i.test(callee)) {
          hasWeakCrypto = true;
          issues.push({
            ruleId: `${language.toLowerCase()}:S4790`,
            title: `Algoritmo criptográfico fraco em ${callee} (${language})`,
            description: 'MD5/SHA-1 possuem colisões conhecidas.',
            category: 'SAST',
            severity: 'CRITICAL',
            cwe: 'CWE-328',
            filePath,
            lineNumber: tok.line,
            endLineNumber: tok.line,
            snippet,
            remediation: 'Utilizar SHA-256/512, AES-256-GCM ou Argon2id.',
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 20,
          });
        }
        if (/AES|GCM|PBKDF2|Argon2/i.test(snippet)) hasCrypto = true;
      }

      // Hardcoded secret assignment
      if (tok.type === 'IDENT' && tokens[idx + 1]?.value === '=' && tokens[idx + 2]?.type === 'STRING') {
        const raw = tokens[idx + 2]!.value.slice(1, -1);
        if (SECRET_IDENTIFIER_HINT.test(tok.value) && raw.length >= 12 && !PLACEHOLDER_SECRET_HINT.test(raw) && shannonEntropy(raw) >= 2.8) {
          issues.push({
            ruleId: `${language.toLowerCase()}:S6418`,
            title: `Credencial hardcoded detectada em ${tok.value} (${language})`,
            description: 'Literal string de alta entropia atribuído diretamente no código.',
            category: 'SECRETS',
            severity: 'BLOCKER',
            cwe: 'CWE-798',
            filePath,
            lineNumber: tok.line,
            endLineNumber: tok.line,
            snippet: (lines[tok.line - 1] || '').trim(),
            remediation: 'Mover segredo para cofre/variável de ambiente.',
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 25,
          });
        }
      }
    }

    return {
      filePath,
      language,
      astParsed: true,
      parserKind: 'STRUCTURAL_PARSER',
      errorCount: 0,
      parserEngine: `winhood-${language.toLowerCase()}-structural-ast-v1`,
      loc: lines.filter((l) => l.trim().length > 0 && !l.trim().startsWith('//')).length,
      cyclomaticComplexity: cyclomatic,
      cognitiveComplexity: cognitive,
      imports,
      functions,
      callSites,
      issues,
      hasAuditSignals: false,
      hasCryptoSignals: hasCrypto,
      hasWeakCryptoSignals: hasWeakCrypto,
      hasPreparedStatementSignals: hasPrepared,
    };
  }

  private static parseSqlAst(filePath: string, content: string): AstParseResult {
    const sqlKeywords = new Set([
      'SELECT', 'FROM', 'WHERE', 'CREATE', 'TABLE', 'INDEX', 'INSERT', 'UPDATE', 'DELETE',
      'DROP', 'ALTER', 'JOIN', 'ON', 'VALUES', 'INTO', 'PRIMARY', 'KEY', 'NOT', 'NULL',
    ]);
    const tokens = tokenizeGenericSource(content, sqlKeywords, false).filter((t) => t.type !== 'COMMENT');
    const lines = content.split(/\r?\n/);
    const issues: AstIssueCandidate[] = [];
    let hasEncryptedColumns = false;

    for (let idx = 0; idx < tokens.length; idx++) {
      const tok = tokens[idx]!;
      const valUpper = tok.value.toUpperCase();

      // Detect SELECT *
      if (tok.type === 'KEYWORD' && valUpper === 'SELECT' && tokens[idx + 1]?.value === '*') {
        issues.push({
          ruleId: 'sql:S1999',
          title: 'SELECT * sem lista explícita de colunas em SQL',
          description: 'Uso de SELECT * aumenta acoplamento ao schema físico e pode expor colunas sensíveis.',
          category: 'DATABASE',
          severity: 'MEDIUM',
          cwe: 'CWE-200',
          filePath,
          lineNumber: tok.line,
          endLineNumber: tok.line,
          snippet: (lines[tok.line - 1] || '').trim(),
          remediation: 'Listar explicitamente apenas as colunas necessárias na projeção SELECT.',
          detectionMethod: 'AST_ANALYSIS',
          confidence: 'HIGH',
          effortMinutes: 10,
        });
      }

      // Plaintext password column in DDL
      if (tok.type === 'IDENT' && /^(password_plain|senha_texto|plain_password|raw_secret)$/i.test(tok.value)) {
        issues.push({
          ruleId: 'sql:S2068',
          title: `Coluna de segredo em texto plano no schema SQL: "${tok.value}"`,
          description: 'Armazenamento de credenciais sem cifragem autenticada ou derivação KDF viola proteção de dados.',
          category: 'DATABASE',
          severity: 'CRITICAL',
          cwe: 'CWE-256',
          filePath,
          lineNumber: tok.line,
          endLineNumber: tok.line,
          snippet: (lines[tok.line - 1] || '').trim(),
          remediation: 'Armazenar ciphertext_hex + iv_hex + auth_tag_hex + kdf_salt_hex.',
          detectionMethod: 'AST_ANALYSIS',
          confidence: 'HIGH',
          effortMinutes: 30,
        });
      }

      if (tok.type === 'IDENT' && /^(ciphertext_hex|auth_tag_hex|kdf_salt_hex)$/i.test(tok.value)) {
        hasEncryptedColumns = true;
      }

      // UPDATE or DELETE without WHERE
      if (tok.type === 'KEYWORD' && (valUpper === 'DELETE' || valUpper === 'UPDATE')) {
        let j = idx + 1;
        let sawWhere = false;
        while (j < tokens.length && tokens[j]!.value !== ';') {
          if (tokens[j]!.type === 'KEYWORD' && tokens[j]!.value.toUpperCase() === 'WHERE') {
            sawWhere = true;
            break;
          }
          j += 1;
        }
        if (!sawWhere) {
          issues.push({
            ruleId: 'sql:S2257',
            title: `Instrução SQL ${valUpper} sem cláusula WHERE`,
            description: 'Mutação em massa sem predicado WHERE pode corromper ou apagar toda a tabela.',
            category: 'DATABASE',
            severity: 'HIGH',
            cwe: 'CWE-404',
            filePath,
            lineNumber: tok.line,
            endLineNumber: tok.line,
            snippet: (lines[tok.line - 1] || '').trim(),
            remediation: `Adicionar cláusula WHERE restritiva na instrução ${valUpper}.`,
            detectionMethod: 'AST_ANALYSIS',
            confidence: 'HIGH',
            effortMinutes: 15,
          });
        }
      }
    }

    return {
      filePath,
      language: 'SQL',
      astParsed: true,
      parserKind: 'STRUCTURAL_PARSER',
      errorCount: 0,
      parserEngine: 'winhood-sql-token-ast-v1',
      loc: lines.filter((l) => l.trim().length > 0 && !l.trim().startsWith('--')).length,
      cyclomaticComplexity: 1,
      cognitiveComplexity: 0,
      imports: [],
      functions: [],
      callSites: [],
      issues,
      hasAuditSignals: false,
      hasCryptoSignals: hasEncryptedColumns,
      hasWeakCryptoSignals: false,
      hasPreparedStatementSignals: false,
    };
  }
}
