import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { build } from 'esbuild';

const rootDir = process.cwd();
const distServerDir = path.join(rootDir, 'dist-server');
const outServerFile = path.join(distServerDir, 'server.mjs');
const outWorkerFile = path.join(distServerDir, 'scanner-worker.mjs');

async function bundleEntry(label, entryPath, outFile) {
  console.log(`[WinHood Server Build] Bundling ${label} (${path.relative(rootDir, outFile)})...`);
  await build({
    entryPoints: [entryPath],
    outfile: outFile,
    bundle: true,
    platform: 'node',
    target: 'node22',
    format: 'esm',
    packages: 'external',
    sourcemap: false,
  });

  if (!fs.existsSync(outFile) || fs.statSync(outFile).size === 0) {
    throw new Error(`Standalone bundle missing or empty: ${outFile}`);
  }

  const bundleContent = fs.readFileSync(outFile, 'utf8');
  const hasStaticViteImport = (() => {
    const lines = bundleContent.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const trimmed = lines[i].trimStart();
      if (!trimmed.startsWith('import ') && !trimmed.startsWith('import{') && !trimmed.startsWith('import*')) {
        continue;
      }
      // Inspect up to 8 lines for a multi-line static import statement ending in from "vite" / 'vite'
      const windowText = lines.slice(i, i + 8).join(' ');
      const semiIdx = windowText.indexOf(';');
      const stmt = semiIdx >= 0 ? windowText.slice(0, semiIdx) : windowText;
      if (stmt.includes('from "vite"') || stmt.includes("from 'vite'")) {
        return true;
      }
    }
    return false;
  })();
  if (hasStaticViteImport) {
    throw new Error(
      `Standalone bundle ${outFile} must not contain a static top-level import from "vite". Use dynamic await import("vite") only in dev middleware mode.`
    );
  }

  const sizeBytes = fs.statSync(outFile).size;
  const sha256 = crypto.createHash('sha256').update(bundleContent, 'utf8').digest('hex');
  console.log(
    `[WinHood Server Build] Completed: ${path.relative(rootDir, outFile)} (${(sizeBytes / 1024).toFixed(1)} KB, sha256=${sha256.slice(0, 16)}...)`
  );
}

async function runServerBuild() {
  fs.mkdirSync(distServerDir, { recursive: true });
  await bundleEntry('standalone Node.js ESM server', path.join(rootDir, 'server.ts'), outServerFile);
  await bundleEntry(
    'isolated scanner worker service',
    path.join(rootDir, 'src', 'worker', 'scannerWorkerServer.ts'),
    outWorkerFile
  );
}

runServerBuild().catch((err) => {
  console.error('[WinHood Server Build Error]:', err);
  process.exit(1);
});
