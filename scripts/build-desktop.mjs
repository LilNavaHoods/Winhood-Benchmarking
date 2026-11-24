import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { build } from 'esbuild';

const rootDir = process.cwd();
const distFrontendDir = path.join(rootDir, 'dist');
const distDesktopDir = path.join(rootDir, 'dist-desktop');

function computeFileSha256(filePath) {
  const buf = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

async function runDesktopBuild() {
  console.log('[WinHood Desktop Build] 0/4 Verifying browser-safe frontend dependency graph...');
  execFileSync(process.execPath, [path.join(rootDir, 'scripts', 'check-browser-imports.mjs')], {
    cwd: rootDir,
    stdio: 'inherit',
  });

  console.log('[WinHood Desktop Build] 1/4 Building frontend bundle via Vite...');
  const npxBin = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  execFileSync(npxBin, ['vite', 'build'], {
    cwd: rootDir,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });

  if (!fs.existsSync(path.join(distFrontendDir, 'index.html'))) {
    throw new Error('Frontend build failed: dist/index.html was not generated.');
  }

  fs.mkdirSync(distDesktopDir, { recursive: true });

  console.log('[WinHood Desktop Build] 2/4 Bundling backend server (dist-desktop/server.mjs)...');
  await build({
    entryPoints: [path.join(rootDir, 'server.ts')],
    outfile: path.join(distDesktopDir, 'server.mjs'),
    bundle: true,
    platform: 'node',
    target: 'node22',
    format: 'esm',
    packages: 'external',
    sourcemap: true,
  });

  console.log('[WinHood Desktop Build] 3/4 Bundling Electron main process (dist-desktop/electron-main.mjs)...');
  await build({
    entryPoints: [path.join(rootDir, 'electron-main.ts')],
    outfile: path.join(distDesktopDir, 'electron-main.mjs'),
    bundle: true,
    platform: 'node',
    target: 'node22',
    format: 'esm',
    packages: 'external',
    sourcemap: true,
  });

  console.log('[WinHood Desktop Build] 4/4 Bundling Electron preload bridge (dist-desktop/electron-preload.cjs)...');
  const preloadOutfile = path.join(distDesktopDir, 'electron-preload.cjs');
  await build({
    entryPoints: [path.join(rootDir, 'electron-preload.ts')],
    outfile: preloadOutfile,
    bundle: true,
    platform: 'node',
    target: 'node22',
    format: 'cjs',
    external: ['electron'],
    sourcemap: false,
  });
  const preloadRaw = fs.readFileSync(preloadOutfile, 'utf8');
  const preloadSanitized = preloadRaw.replace(
    /0 && \(module\.exports = \{([\s\S]*?)\}\);/g,
    'if (typeof module !== "undefined" && module.exports) {\n  module.exports = {$1};\n}'
  );
  if (preloadSanitized !== preloadRaw) {
    fs.writeFileSync(preloadOutfile, preloadSanitized, 'utf8');
  }

  const requiredFiles = [
    path.join(distFrontendDir, 'index.html'),
    path.join(distDesktopDir, 'server.mjs'),
    path.join(distDesktopDir, 'electron-main.mjs'),
    path.join(distDesktopDir, 'electron-preload.cjs'),
  ];

  const artifacts = {};
  for (const file of requiredFiles) {
    if (!fs.existsSync(file) || fs.statSync(file).size === 0) {
      throw new Error(`Missing or empty desktop build artifact: ${file}`);
    }
    const rel = path.relative(rootDir, file).replace(/\\/g, '/');
    artifacts[rel] = {
      sizeBytes: fs.statSync(file).size,
      sha256: computeFileSha256(file),
    };
  }

  const pkg = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
  const commitSha = (process.env.GITHUB_SHA || process.env.COMMIT_SHA || '').trim() || 'UNAVAILABLE';

  const manifest = {
    schemaVersion: '2.0.0',
    packageName: pkg.name,
    version: pkg.version,
    commitSha,
    builtAt: new Date().toISOString(),
    buildEnvironment: {
      nodeVersion: process.version,
      platform: process.platform,
      arch: process.arch,
      ci: Boolean(process.env.CI),
    },
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    artifacts,
  };

  const manifestJson = JSON.stringify(manifest, null, 2);
  const manifestPath = path.join(distDesktopDir, 'build-manifest.json');
  fs.writeFileSync(manifestPath, manifestJson, 'utf8');

  const provenance = {
    predicateType: 'https://winhood.local/provenance/desktop-build/v1',
    subject: {
      packageName: pkg.name,
      version: pkg.version,
      commitSha,
      manifestPath: 'dist-desktop/build-manifest.json',
      manifestSha256: crypto.createHash('sha256').update(manifestJson, 'utf8').digest('hex'),
    },
    artifactsSha256: Object.fromEntries(
      Object.entries(artifacts).map(([rel, info]) => [rel, info.sha256])
    ),
    generatedAt: manifest.builtAt,
  };
  const provenancePath = path.join(distDesktopDir, 'provenance-attestation.json');
  fs.writeFileSync(provenancePath, JSON.stringify(provenance, null, 2), 'utf8');
  console.log('[WinHood Desktop Build] Completed successfully. Manifest:', manifestPath, '| Provenance:', provenancePath);
}

runDesktopBuild().catch((err) => {
  console.error('[WinHood Desktop Build Error]:', err);
  process.exit(1);
});
