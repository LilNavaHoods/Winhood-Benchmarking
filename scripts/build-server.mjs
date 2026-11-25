import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { build } from 'esbuild';

const rootDir = process.cwd();
const distServerDir = path.join(rootDir, 'dist-server');
const outFile = path.join(distServerDir, 'server.mjs');

async function runServerBuild() {
  fs.mkdirSync(distServerDir, { recursive: true });

  console.log('[WinHood Server Build] Bundling standalone Node.js ESM server (dist-server/server.mjs)...');
  await build({
    entryPoints: [path.join(rootDir, 'server.ts')],
    outfile: outFile,
    bundle: true,
    platform: 'node',
    target: 'node22',
    format: 'esm',
    packages: 'external',
    sourcemap: false,
  });

  if (!fs.existsSync(outFile) || fs.statSync(outFile).size === 0) {
    throw new Error(`Standalone server bundle missing or empty: ${outFile}`);
  }

  const bundleContent = fs.readFileSync(outFile, 'utf8');
  if (/^\s*import\s+[\s\S]*?\s+from\s+["']vite["']/m.test(bundleContent)) {
    throw new Error(
      'Standalone server bundle must not contain a static top-level import from "vite". Use dynamic await import("vite") only in dev middleware mode.'
    );
  }

  const sizeBytes = fs.statSync(outFile).size;
  const sha256 = crypto.createHash('sha256').update(bundleContent, 'utf8').digest('hex');
  console.log(
    `[WinHood Server Build] Completed: dist-server/server.mjs (${(sizeBytes / 1024).toFixed(1)} KB, sha256=${sha256.slice(0, 16)}...)`
  );
}

runServerBuild().catch((err) => {
  console.error('[WinHood Server Build Error]:', err);
  process.exit(1);
});
