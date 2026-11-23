import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  analyzeBrowserDependencyGraph,
  extractRuntimeSpecifiersFromSource,
  isForbiddenBrowserSpecifier,
  loadModuleAliases,
  loadTsconfigPathAliases,
  loadViteAliases,
} from './check-browser-imports.mjs';

function makeTempProject(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-browser-checker-test-'));
  for (const [relPath, content] of Object.entries(files)) {
    const abs = path.join(root, relPath);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, 'utf8');
  }
  return root;
}

test('isForbiddenBrowserSpecifier classifies Node builtins, node:* prefixes, subpaths, and server packages accurately', () => {
  const forbidden = [
    'node:child_process',
    'child_process',
    'node:fs',
    'fs',
    'fs/promises',
    'node:fs/promises',
    'node:net',
    'net',
    'node:dns',
    'dns/promises',
    'node:worker_threads',
    'worker_threads',
    'node:os',
    'os',
    'node:crypto',
    'crypto',
    'node:path',
    'express',
    'electron',
    'dotenv',
    'better-sqlite3',
  ];
  for (const spec of forbidden) {
    assert.equal(isForbiddenBrowserSpecifier(spec), true, `Expected "${spec}" to be forbidden`);
  }

  const allowed = [
    'react',
    'react-dom/client',
    'lucide-react',
    './benchmarkWeights',
    '../shared/benchmarkConfig',
    '@/src/shared/benchmarkCategories',
    '/src/main.tsx',
  ];
  for (const spec of allowed) {
    assert.equal(isForbiddenBrowserSpecifier(spec), false, `Expected "${spec}" to be allowed`);
  }
});

test('extractRuntimeSpecifiersFromSource captures static, re-export, dynamic, and require while ignoring type-only imports', () => {
  const specs = extractRuntimeSpecifiersFromSource(
    'example.tsx',
    `
      import type { ChildProcess } from 'node:child_process';
      import { type Stats, type Dirent } from 'node:fs';
      export type { KeyObject } from 'node:crypto';
      export { type Server } from 'node:net';
      import React from 'react';
      import { normalize } from './weights';
      export * from './barrel';
      export * as ns from './namespace';
      export { helper } from './reexport';
      async function lazy() { return import('node:dns'); }
      const cjs = require('node:worker_threads');
    `
  );

  const bySpecifier = new Map(specs.map((s) => [s.specifier, s.kind]));
  assert.equal(bySpecifier.has('node:child_process'), false);
  assert.equal(bySpecifier.has('node:fs'), false);
  assert.equal(bySpecifier.has('node:crypto'), false);
  assert.equal(bySpecifier.has('node:net'), false);

  assert.equal(bySpecifier.get('react'), 'static-import');
  assert.equal(bySpecifier.get('./weights'), 'static-import');
  assert.equal(bySpecifier.get('./barrel'), 're-export');
  assert.equal(bySpecifier.get('./namespace'), 're-export');
  assert.equal(bySpecifier.get('./reexport'), 're-export');
  assert.equal(bySpecifier.get('node:dns'), 'dynamic-import');
  assert.equal(bySpecifier.get('node:worker_threads'), 'require');
});

test('Checker passes on clean browser graph spanning .ts, .tsx, .js, .jsx, .mjs, barrels, type-only imports, and cycles', () => {
  const tmpRoot = makeTempProject({
    'index.html': '<!doctype html><html><body><script type="module" src="/src/main.tsx"></script></body></html>',
    'tsconfig.json': JSON.stringify({
      compilerOptions: {
        paths: {
          '@/*': ['./*'],
          '@shared/*': ['./src/shared/*'],
        },
      },
    }),
    'src/main.tsx': `
      import type { SpawnSyncReturns } from 'node:child_process';
      import { App } from '/src/App';
      export type Unused = SpawnSyncReturns<string>;
      export { App };
    `,
    'src/App.tsx': `
      import { Widget } from './components/Widget.jsx';
      import { calc } from '@shared/index';
      import { cycleB } from './utils/cycleA.js';
      export const App = () => [Widget(), calc(), cycleB()];
    `,
    'src/components/Widget.jsx': `
      import { fmt } from '../utils/format.mjs';
      export const Widget = () => fmt('ok');
    `,
    'src/shared/index.ts': `export * from './math';\n`,
    'src/shared/math.js': `export const calc = () => 100;\n`,
    'src/utils/format.mjs': `export const fmt = (v) => String(v);\n`,
    'src/utils/cycleA.ts': `import { cycleA } from './cycleB'; export const cycleB = () => cycleA;\n`,
    'src/utils/cycleB.ts': `import { cycleB } from './cycleA'; export const cycleA = () => cycleB;\n`,
  });

  try {
    const report = analyzeBrowserDependencyGraph({ rootDir: tmpRoot });
    assert.equal(report.ok, true, `Unexpected violations: ${JSON.stringify(report.violations)}`);
    assert.equal(report.violations.length, 0);
    assert.ok(report.scannedFiles.includes('src/main.tsx'));
    assert.ok(report.scannedFiles.includes('src/App.tsx'));
    assert.ok(report.scannedFiles.includes('src/components/Widget.jsx'));
    assert.ok(report.scannedFiles.includes('src/shared/math.js'));
    assert.ok(report.scannedFiles.includes('src/utils/format.mjs'));
    assert.ok(report.scannedFiles.includes('src/utils/cycleA.ts'));
    assert.ok(report.scannedFiles.includes('src/utils/cycleB.ts'));
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test('Checker detects direct and transitive regressions through Vite aliases, tsconfig aliases, barrels, dynamic import, and require', () => {
  const tmpRoot = makeTempProject({
    'index.html': '<!doctype html><script type="module" src="/src/main.tsx"></script>',
    'vite.config.ts': `
      import path from 'path';
      export default {
        resolve: {
          alias: {
            '@vite-engine': path.resolve(__dirname, 'src/server-engine'),
          },
        },
      };
    `,
    'tsconfig.json': JSON.stringify({
      compilerOptions: {
        paths: {
          '@alias/*': ['./src/aliased/*'],
        },
      },
    }),
    'src/main.tsx': `
      import { Wizard } from './components/Wizard';
      export { Wizard };
    `,
    'src/components/Wizard.tsx': `
      import { score } from '@vite-engine';
      import { loadNet } from '@alias/network';
      export const Wizard = () => [score(), loadNet()];
    `,
    'src/server-engine/index.ts': `export { score } from './keyVault.js';\n`,
    'src/server-engine/keyVault.ts': `
      import { spawnSync } from 'node:child_process';
      export const score = () => spawnSync('uname');
    `,
    'src/aliased/network.ts': `
      export async function loadNet() {
        const net = await import('node:net');
        const fsMod = require('fs');
        return { net, fsMod };
      }
    `,
  });

  try {
    const viteAliases = loadViteAliases(tmpRoot);
    assert.ok(viteAliases.some((a) => a.exact === '@vite-engine'));
    const tsAliases = loadTsconfigPathAliases(tmpRoot);
    assert.ok(tsAliases.some((a) => a.prefix === '@alias/'));
    assert.ok(loadModuleAliases(tmpRoot).length >= 2);

    const report = analyzeBrowserDependencyGraph({ rootDir: tmpRoot });
    assert.equal(report.ok, false);

    const specifiers = report.violations.map((v) => v.specifier).sort();
    assert.deepEqual(specifiers, ['fs', 'node:child_process', 'node:net']);

    const cpViolation = report.violations.find((v) => v.specifier === 'node:child_process');
    assert.ok(cpViolation);
    assert.ok(
      cpViolation.chain.includes('src/server-engine/index.ts') &&
        cpViolation.chain.includes('src/server-engine/keyVault.ts'),
      `Expected full transitive barrel chain, got: ${cpViolation.chain.join(' -> ')}`
    );
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test('CLI execution exits with code 0 on real WinHood repo and exits with code 1 when a Node-only regression exists', () => {
  const scriptPath = path.resolve(process.cwd(), 'scripts', 'check-browser-imports.mjs');

  // 1. Live WinHood repository must exit 0
  const okRun = spawnSync(process.execPath, [scriptPath], {
    cwd: process.cwd(),
    encoding: 'utf8',
  });
  assert.equal(okRun.status, 0, `Expected exit 0 on real repo, stderr: ${okRun.stderr}`);
  assert.ok(okRun.stdout.includes('[check:browser-imports] PASSED'));

  // 2. Regression fixture must exit 1 (which blocks `npm run build`)
  const badRoot = makeTempProject({
    'src/main.tsx': `import { Worker } from 'node:worker_threads'; export const w = Worker;\n`,
  });
  try {
    const failRun = spawnSync(process.execPath, [scriptPath, '--root', badRoot], {
      cwd: process.cwd(),
      encoding: 'utf8',
    });
    assert.equal(failRun.status, 1, 'Expected exit 1 when forbidden Node module is reachable');
    assert.ok(failRun.stderr.includes('[check:browser-imports] FAILED'));
    assert.ok(failRun.stderr.includes('node:worker_threads'));
  } finally {
    fs.rmSync(badRoot, { recursive: true, force: true });
  }
});
