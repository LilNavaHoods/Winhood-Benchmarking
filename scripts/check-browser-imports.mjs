/**
 * WinHood Automated Browser-Safe Import Graph Checker
 *
 * Parses TypeScript/JavaScript ASTs (via the official TypeScript compiler API)
 * starting from frontend entry points (index.html / src/main.tsx + all client
 * UI, shared, and utility modules) and traverses static imports, re-exports,
 * barrel files, dynamic `import(...)`, and `require(...)` across `.ts`, `.tsx`,
 * `.js`, `.jsx`, `.mjs`, and `.cjs` files — resolving both tsconfig.json and
 * vite.config.* path aliases as well as TypeScript ESM `.js -> .ts` imports.
 *
 * Fails with exit code 1 if any Node.js built-in module (e.g., `node:child_process`,
 * `child_process`, `node:fs`, `fs`, `node:net`, `node:dns`, `node:os`, `node:crypto`,
 * `node:worker_threads`, etc.) or forbidden server-only package (`express`, `electron`,
 * `esbuild`, `tsx`, `dotenv`, `sqlite3`, `better-sqlite3`, `keytar`) is reachable in
 * runtime client code.
 */

import fs from 'node:fs';
import { builtinModules } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const RESOLVABLE_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'];
const ESM_JS_TO_TS_FALLBACKS = {
  '.js': ['.ts', '.tsx', '.js', '.jsx'],
  '.jsx': ['.tsx', '.jsx'],
  '.mjs': ['.mts', '.ts', '.mjs'],
  '.cjs': ['.cts', '.ts', '.cjs'],
};

export const NODE_BUILTIN_SET = new Set([
  ...builtinModules,
  ...builtinModules.map((m) => (m.startsWith('node:') ? m : `node:${m}`)),
  ...builtinModules.map((m) => (m.startsWith('node:') ? m.slice(5) : m)),
]);

export const FORBIDDEN_SERVER_PACKAGES = new Set([
  'express',
  'electron',
  'esbuild',
  'tsx',
  'dotenv',
  'sqlite3',
  'better-sqlite3',
  'keytar',
]);

export function isForbiddenBrowserSpecifier(specifier) {
  if (!specifier || typeof specifier !== 'string') return false;
  const clean = specifier.trim();
  if (clean.startsWith('node:')) return true;
  if (NODE_BUILTIN_SET.has(clean)) return true;
  const rootPkg = clean.startsWith('@')
    ? clean.split('/').slice(0, 2).join('/')
    : clean.split('/')[0];
  if (NODE_BUILTIN_SET.has(rootPkg)) return true;
  if (FORBIDDEN_SERVER_PACKAGES.has(rootPkg)) return true;
  return false;
}

function getScriptKind(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.tsx') return ts.ScriptKind.TSX;
  if (ext === '.jsx') return ts.ScriptKind.JSX;
  if (ext === '.js' || ext === '.mjs' || ext === '.cjs') return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

/**
 * Extracts all runtime module specifiers from a source file using the TypeScript AST.
 * Ignores pure `import type` / `export type` declarations (erased before browser bundling).
 */
export function extractRuntimeSpecifiersFromSource(filePath, sourceText) {
  const sourceFile = ts.createSourceFile(
    filePath,
    sourceText,
    ts.ScriptTarget.Latest,
    true,
    getScriptKind(filePath)
  );

  /** @type {Array<{ specifier: string; kind: 'static-import' | 're-export' | 'dynamic-import' | 'require'; line: number }>} */
  const specifiers = [];

  const record = (specifier, kind, node) => {
    const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
    specifiers.push({ specifier, kind, line: pos.line + 1 });
  };

  const visit = (node) => {
    // 1. Static import declarations: import ... from '...' / import '...'
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const clause = node.importClause;
      let isTypeOnly = false;
      if (clause) {
        if (clause.isTypeOnly) {
          isTypeOnly = true;
        } else if (
          !clause.name &&
          clause.namedBindings &&
          ts.isNamedImports(clause.namedBindings) &&
          clause.namedBindings.elements.length > 0 &&
          clause.namedBindings.elements.every((el) => el.isTypeOnly)
        ) {
          isTypeOnly = true;
        }
      }
      if (!isTypeOnly) {
        record(node.moduleSpecifier.text, 'static-import', node.moduleSpecifier);
      }
    }

    // 2. Re-exports: export * from '...' / export * as ns from '...' / export { a } from '...'
    if (
      ts.isExportDeclaration(node) &&
      node.moduleSpecifier &&
      ts.isStringLiteral(node.moduleSpecifier)
    ) {
      let isTypeOnly = Boolean(node.isTypeOnly);
      if (
        !isTypeOnly &&
        node.exportClause &&
        ts.isNamedExports(node.exportClause) &&
        node.exportClause.elements.length > 0 &&
        node.exportClause.elements.every((el) => el.isTypeOnly)
      ) {
        isTypeOnly = true;
      }
      if (!isTypeOnly) {
        record(node.moduleSpecifier.text, 're-export', node.moduleSpecifier);
      }
    }

    // 3. Dynamic import('...') & CommonJS require('...')
    if (ts.isCallExpression(node) && node.arguments.length >= 1) {
      const firstArg = node.arguments[0];
      if (firstArg && ts.isStringLiteralLike(firstArg)) {
        if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
          record(firstArg.text, 'dynamic-import', firstArg);
        } else if (ts.isIdentifier(node.expression) && node.expression.text === 'require') {
          record(firstArg.text, 'require', firstArg);
        }
      }
    }

    // 4. TS import = require('...')
    if (
      ts.isImportEqualsDeclaration(node) &&
      !node.isTypeOnly &&
      ts.isExternalModuleReference(node.moduleReference) &&
      ts.isStringLiteral(node.moduleReference.expression)
    ) {
      record(node.moduleReference.expression.text, 'require', node.moduleReference.expression);
    }

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return specifiers;
}

export function loadTsconfigPathAliases(rootDir) {
  const tsconfigPath = path.join(rootDir, 'tsconfig.json');
  if (!fs.existsSync(tsconfigPath)) return [];
  try {
    const parsed = ts.readConfigFile(tsconfigPath, (p) => fs.readFileSync(p, 'utf8'));
    const paths = parsed.config?.compilerOptions?.paths || {};
    const baseUrl = parsed.config?.compilerOptions?.baseUrl
      ? path.resolve(rootDir, parsed.config.compilerOptions.baseUrl)
      : rootDir;
    const aliases = [];
    for (const [pattern, targets] of Object.entries(paths)) {
      if (!Array.isArray(targets) || targets.length === 0) continue;
      if (pattern.endsWith('/*')) {
        const prefix = pattern.slice(0, -1); // e.g. "@/"
        const targetPrefix = String(targets[0]).replace(/\*$/, '');
        aliases.push({ prefix, targetDir: path.resolve(baseUrl, targetPrefix) });
      } else {
        aliases.push({
          exact: pattern,
          targetPath: path.resolve(baseUrl, String(targets[0])),
        });
      }
    }
    return aliases;
  } catch {
    return [];
  }
}

function evalSimplePathExpression(node, rootDir) {
  if (!node) return null;
  if (ts.isStringLiteralLike(node)) {
    return path.resolve(rootDir, node.text);
  }
  // Support path.resolve(__dirname / import.meta.dirname, 'src', ...) or path.join(...)
  if (ts.isCallExpression(node) && node.arguments.length >= 1) {
    const exprText = node.expression.getText();
    if (exprText.endsWith('resolve') || exprText.endsWith('join')) {
      const segments = [];
      for (const arg of node.arguments) {
        if (ts.isStringLiteralLike(arg)) {
          segments.push(arg.text);
        } else {
          const raw = arg.getText();
          if (raw === '__dirname' || raw === 'import.meta.dirname' || raw === 'process.cwd()') {
            segments.push(rootDir);
          }
        }
      }
      if (segments.length > 0) {
        return path.resolve(rootDir, ...segments);
      }
    }
  }
  return null;
}

function pushViteAliasEntry(aliases, findKey, replacementPath) {
  if (!findKey || !replacementPath) return;
  const normalizedFind = findKey.trim();
  if (!normalizedFind) return;
  if (normalizedFind.endsWith('/')) {
    aliases.push({ prefix: normalizedFind, targetDir: replacementPath });
  } else {
    aliases.push({ exact: normalizedFind, targetPath: replacementPath });
    aliases.push({ prefix: `${normalizedFind}/`, targetDir: replacementPath });
  }
}

/**
 * Parses Vite `resolve.alias` entries (both object-map and `{ find, replacement }` array syntax)
 * from `vite.config.{ts,mts,mjs,js}` using the TypeScript AST.
 */
export function loadViteAliases(rootDir) {
  const candidates = ['vite.config.ts', 'vite.config.mts', 'vite.config.mjs', 'vite.config.js'];
  const viteConfigPath = candidates
    .map((f) => path.join(rootDir, f))
    .find((p) => fs.existsSync(p) && fs.statSync(p).isFile());
  if (!viteConfigPath) return [];

  try {
    const content = fs.readFileSync(viteConfigPath, 'utf8');
    const sourceFile = ts.createSourceFile(
      viteConfigPath,
      content,
      ts.ScriptTarget.Latest,
      true,
      getScriptKind(viteConfigPath)
    );
    const aliases = [];

    const visit = (node) => {
      if (
        ts.isPropertyAssignment(node) &&
        ((ts.isIdentifier(node.name) && node.name.text === 'alias') ||
          (ts.isStringLiteral(node.name) && node.name.text === 'alias'))
      ) {
        const init = node.initializer;
        if (ts.isObjectLiteralExpression(init)) {
          for (const prop of init.properties) {
            if (!ts.isPropertyAssignment(prop)) continue;
            const key =
              ts.isStringLiteralLike(prop.name) || ts.isIdentifier(prop.name)
                ? prop.name.text
                : null;
            const target = evalSimplePathExpression(prop.initializer, rootDir);
            if (key && target) {
              pushViteAliasEntry(aliases, key, target);
            }
          }
        } else if (ts.isArrayLiteralExpression(init)) {
          for (const elem of init.elements) {
            if (!ts.isObjectLiteralExpression(elem)) continue;
            let findKey = null;
            let replacement = null;
            for (const prop of elem.properties) {
              if (!ts.isPropertyAssignment(prop)) continue;
              const propName =
                ts.isIdentifier(prop.name) || ts.isStringLiteralLike(prop.name)
                  ? prop.name.text
                  : null;
              if (propName === 'find' && ts.isStringLiteralLike(prop.initializer)) {
                findKey = prop.initializer.text;
              } else if (propName === 'replacement') {
                replacement = evalSimplePathExpression(prop.initializer, rootDir);
              }
            }
            if (findKey && replacement) {
              pushViteAliasEntry(aliases, findKey, replacement);
            }
          }
        }
      }
      ts.forEachChild(node, visit);
    };

    visit(sourceFile);
    return aliases;
  } catch {
    return [];
  }
}

export function loadModuleAliases(rootDir) {
  const combined = [...loadTsconfigPathAliases(rootDir), ...loadViteAliases(rootDir)];
  const seen = new Set();
  return combined.filter((entry) => {
    const sig = entry.prefix
      ? `p:${entry.prefix}=>${entry.targetDir}`
      : `e:${entry.exact}=>${entry.targetPath}`;
    if (seen.has(sig)) return false;
    seen.add(sig);
    return true;
  });
}

function resolveCandidateFile(baseCandidate) {
  // Exact file match
  if (fs.existsSync(baseCandidate) && fs.statSync(baseCandidate).isFile()) {
    return baseCandidate;
  }

  // TypeScript ESM extension mapping (e.g. `./foo.js` -> `./foo.ts` / `./foo.tsx`)
  const ext = path.extname(baseCandidate).toLowerCase();
  const mappedExts = ESM_JS_TO_TS_FALLBACKS[ext];
  if (mappedExts) {
    const stem = baseCandidate.slice(0, -ext.length);
    for (const candidateExt of mappedExts) {
      const mapped = `${stem}${candidateExt}`;
      if (fs.existsSync(mapped) && fs.statSync(mapped).isFile()) {
        return mapped;
      }
    }
  }

  // Try adding resolvable extensions
  for (const candidateExt of RESOLVABLE_EXTENSIONS) {
    const withExt = `${baseCandidate}${candidateExt}`;
    if (fs.existsSync(withExt) && fs.statSync(withExt).isFile()) {
      return withExt;
    }
  }

  // Try directory index.* (barrel files)
  if (fs.existsSync(baseCandidate) && fs.statSync(baseCandidate).isDirectory()) {
    for (const candidateExt of RESOLVABLE_EXTENSIONS) {
      const idxFile = path.join(baseCandidate, `index${candidateExt}`);
      if (fs.existsSync(idxFile) && fs.statSync(idxFile).isFile()) {
        return idxFile;
      }
    }
  }
  return null;
}

function resolveLocalModule(fromFile, specifier, rootDir, aliases) {
  // Strip query strings / hashes (e.g., ?raw, ?url)
  const cleanSpec = specifier.split('?')[0].split('#')[0];

  // Relative import
  if (cleanSpec.startsWith('./') || cleanSpec.startsWith('../') || cleanSpec === '.' || cleanSpec === '..') {
    const base = path.resolve(path.dirname(fromFile), cleanSpec);
    return resolveCandidateFile(base);
  }

  // Root-relative import (e.g., /src/main.tsx)
  if (cleanSpec.startsWith('/')) {
    const base = path.resolve(rootDir, cleanSpec.slice(1));
    return resolveCandidateFile(base);
  }

  // Configured tsconfig/Vite aliases (e.g., @/src/..., @shared/...)
  for (const alias of aliases) {
    if (alias.exact && cleanSpec === alias.exact) {
      const resolved = resolveCandidateFile(alias.targetPath);
      if (resolved) return resolved;
    }
    if (alias.prefix && cleanSpec.startsWith(alias.prefix)) {
      const rest = cleanSpec.slice(alias.prefix.length);
      const base = path.resolve(alias.targetDir, rest);
      const resolved = resolveCandidateFile(base);
      if (resolved) return resolved;
    }
  }

  return null;
}

function collectSourceFilesRecursively(dirPath, out) {
  if (!fs.existsSync(dirPath)) return;
  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    const abs = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '__tests__') {
        continue;
      }
      collectSourceFilesRecursively(abs, out);
      continue;
    }
    if (!entry.isFile()) continue;
    const name = entry.name;
    if (name.includes('.test.') || name.includes('.spec.') || name.endsWith('.d.ts')) continue;
    const ext = path.extname(name).toLowerCase();
    if (!RESOLVABLE_EXTENSIONS.includes(ext)) continue;
    if (!out.includes(abs)) {
      out.push(abs);
    }
  }
}

function discoverDefaultFrontendEntries(rootDir) {
  const entries = [];
  const htmlPath = path.join(rootDir, 'index.html');
  if (fs.existsSync(htmlPath)) {
    const html = fs.readFileSync(htmlPath, 'utf8');
    const scriptRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
    let m;
    while ((m = scriptRegex.exec(html)) !== null) {
      const src = m[1];
      if (!src || src.startsWith('http://') || src.startsWith('https://')) continue;
      const rel = src.startsWith('/') ? src.slice(1) : src;
      const resolved = resolveCandidateFile(path.resolve(rootDir, rel));
      if (resolved && !entries.includes(resolved)) entries.push(resolved);
    }
  }

  for (const candidate of ['src/main.tsx', 'src/main.ts', 'src/App.tsx']) {
    const abs = path.join(rootDir, candidate);
    if (fs.existsSync(abs) && !entries.includes(abs)) {
      entries.push(abs);
    }
  }

  // Recursively include every non-test file in src/components, src/shared, and src/utils
  // so even detached/lazy UI components or shared helpers cannot silently pull Node-only modules.
  for (const subDir of ['src/components', 'src/shared', 'src/utils']) {
    collectSourceFilesRecursively(path.join(rootDir, subDir), entries);
  }

  return entries;
}

/**
 * Analyzes the complete transitive dependency graph reachable from frontend entries.
 *
 * @param {{ rootDir: string; entryPoints?: string[] }} options
 */
export function analyzeBrowserDependencyGraph(options) {
  const rootDir = path.resolve(options.rootDir);
  const aliases = loadModuleAliases(rootDir);
  const entryPoints =
    options.entryPoints && options.entryPoints.length > 0
      ? options.entryPoints.map((e) => path.resolve(rootDir, e))
      : discoverDefaultFrontendEntries(rootDir);

  const visited = new Set();
  const queue = [];

  for (const ep of entryPoints) {
    if (!fs.existsSync(ep)) continue;
    if (!visited.has(ep)) {
      visited.add(ep);
      queue.push({ filePath: ep, chain: [path.relative(rootDir, ep).replace(/\\/g, '/')] });
    }
  }

  /** @type {Array<{ file: string; line: number; specifier: string; kind: string; chain: string[] }>} */
  const violations = [];

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) break;

    let content;
    try {
      content = fs.readFileSync(current.filePath, 'utf8');
    } catch {
      continue;
    }

    const specs = extractRuntimeSpecifiersFromSource(current.filePath, content);
    for (const item of specs) {
      if (isForbiddenBrowserSpecifier(item.specifier)) {
        violations.push({
          file: path.relative(rootDir, current.filePath).replace(/\\/g, '/'),
          line: item.line,
          specifier: item.specifier,
          kind: item.kind,
          chain: [...current.chain, item.specifier],
        });
        continue;
      }

      const resolved = resolveLocalModule(current.filePath, item.specifier, rootDir, aliases);
      if (resolved && !visited.has(resolved)) {
        visited.add(resolved);
        const rel = path.relative(rootDir, resolved).replace(/\\/g, '/');
        queue.push({
          filePath: resolved,
          chain: [...current.chain, rel],
        });
      }
    }
  }

  return {
    rootDir,
    entryPoints: entryPoints.map((e) => path.relative(rootDir, e).replace(/\\/g, '/')),
    filesScannedCount: visited.size,
    scannedFiles: Array.from(visited).map((f) => path.relative(rootDir, f).replace(/\\/g, '/')),
    violations,
    ok: violations.length === 0,
  };
}

// CLI execution when invoked directly
const isDirectExecution =
  process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isDirectExecution) {
  const rootArgIdx = process.argv.indexOf('--root');
  const rootDir =
    rootArgIdx !== -1 && process.argv[rootArgIdx + 1]
      ? path.resolve(process.argv[rootArgIdx + 1])
      : path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const result = analyzeBrowserDependencyGraph({ rootDir });

  if (!result.ok) {
    console.error(
      `[check:browser-imports] FAILED — Found ${result.violations.length} forbidden Node.js/server import(s) reachable from frontend (${result.filesScannedCount} files scanned):`
    );
    for (const v of result.violations) {
      console.error(`  - [${v.kind}] ${v.file}:${v.line} imports "${v.specifier}"`);
      console.error(`    Chain: ${v.chain.join(' -> ')}`);
    }
    process.exit(1);
  }

  console.log(
    `[check:browser-imports] PASSED — ${result.filesScannedCount} frontend/shared modules scanned from ${result.entryPoints.length} entry points. Zero Node.js or server-only imports reachable in browser code.`
  );
}
