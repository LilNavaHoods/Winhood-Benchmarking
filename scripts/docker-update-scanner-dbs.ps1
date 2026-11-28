#Requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error '[WinHood Scanner DB] Docker nao encontrado no PATH.'
    exit 1
}

& docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Error '[WinHood Scanner DB] Daemon Docker nao esta em execucao.'
    exit 1
}

$projectName = ((Split-Path -Leaf $RootDir).ToLower() -replace '[^a-z0-9_-]', '')
$volumeName = if ($env:WINHOOD_SCANNER_CACHE_VOLUME) { $env:WINHOOD_SCANNER_CACHE_VOLUME } else { "${projectName}_winhood_scanner_cache" }
$osvEcosystems = if ($env:WINHOOD_OSV_ECOSYSTEMS) { $env:WINHOOD_OSV_ECOSYSTEMS } else { 'npm PyPI Go Maven NuGet crates.io' }
$dbTtlDays = if ($env:WINHOOD_SCANNER_DB_MAX_AGE_DAYS) { $env:WINHOOD_SCANNER_DB_MAX_AGE_DAYS } else { '30' }

& docker volume inspect $volumeName *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WinHood Scanner DB] Criando volume $volumeName..." -ForegroundColor Cyan
    & docker volume create $volumeName | Out-Null
}

& docker image inspect winhood-scanner-worker:4.4.0 *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host '[WinHood Scanner DB] Construindo imagem winhood-scanner-worker:4.4.0...' -ForegroundColor Cyan
    Push-Location $RootDir
    try {
        & docker compose build winhood-scanner-worker
    } finally {
        Pop-Location
    }
}

Write-Host "[WinHood Scanner DB] Atualizando bases offline do Grype e OSV-Scanner no volume $volumeName..." -ForegroundColor Cyan
$updateCmd = @'
set -euo pipefail
GRYPE_STAGE="/data/scanner-cache/.grype-stage-$$"
rm -rf "${GRYPE_STAGE}"
mkdir -p "${GRYPE_STAGE}" /data/scanner-cache/grype
GRYPE_DB_CACHE_DIR="${GRYPE_STAGE}" /usr/local/bin/grype db update
GRYPE_DB_CACHE_DIR="${GRYPE_STAGE}" /usr/local/bin/grype db status >/dev/null
node -e '
  const fs = require("node:fs");
  const path = require("node:path");
  const crypto = require("node:crypto");
  const stage = process.argv[1];
  const ttlDays = Number(process.argv[2]) || 30;
  const artifacts = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && e.name !== "manifest.json") {
        const buf = fs.readFileSync(full);
        artifacts.push({
          relativePath: path.relative(stage, full).replace(/\\/g, "/"),
          sizeBytes: buf.length,
          sha256: crypto.createHash("sha256").update(buf).digest("hex"),
        });
      }
    }
  };
  walk(stage);
  if (artifacts.length === 0) process.exit(1);
  const now = new Date();
  const manifest = {
    schemaVersion: "1.0.0",
    tool: "grype",
    updatedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlDays * 86400 * 1000).toISOString(),
    artifacts,
  };
  fs.writeFileSync(path.join(stage, "manifest.json"), JSON.stringify(manifest, null, 2));
' "${GRYPE_STAGE}" "${DB_TTL_DAYS}"
rm -rf /data/scanner-cache/grype.prev
if [ -d /data/scanner-cache/grype ]; then mv /data/scanner-cache/grype /data/scanner-cache/grype.prev; fi
mv "${GRYPE_STAGE}" /data/scanner-cache/grype
rm -rf /data/scanner-cache/grype.prev

OSV_STAGE="/data/scanner-cache/.osv-stage-$$"
rm -rf "${OSV_STAGE}"
mkdir -p "${OSV_STAGE}" /data/scanner-cache/osv
for eco in ${OSV_ECOSYSTEMS}; do
  ECO_DIR="${OSV_STAGE}/${eco}"
  mkdir -p "${ECO_DIR}"
  ZIP_PATH="${ECO_DIR}/all.zip"
  curl --proto "=https" --tlsv1.2 -fsSL "https://osv-vulnerabilities.storage.googleapis.com/${eco}/all.zip" -o "${ZIP_PATH}"
  python3 -m zipfile -t "${ZIP_PATH}"
done
node -e '
  const fs = require("node:fs");
  const path = require("node:path");
  const crypto = require("node:crypto");
  const stage = process.argv[1];
  const ttlDays = Number(process.argv[2]) || 30;
  const artifacts = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && e.name.endsWith(".zip")) {
        const buf = fs.readFileSync(full);
        artifacts.push({
          relativePath: path.relative(stage, full).replace(/\\/g, "/"),
          sizeBytes: buf.length,
          sha256: crypto.createHash("sha256").update(buf).digest("hex"),
        });
      }
    }
  };
  walk(stage);
  if (artifacts.length === 0) process.exit(1);
  const now = new Date();
  const manifest = {
    schemaVersion: "1.0.0",
    tool: "osv-scanner",
    updatedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttlDays * 86400 * 1000).toISOString(),
    ecosystems: artifacts.map((a) => a.relativePath.split("/")[0]),
    artifacts,
  };
  fs.writeFileSync(path.join(stage, "manifest.json"), JSON.stringify(manifest, null, 2));
' "${OSV_STAGE}" "${DB_TTL_DAYS}"
rm -rf /data/scanner-cache/osv.prev
if [ -d /data/scanner-cache/osv ]; then mv /data/scanner-cache/osv /data/scanner-cache/osv.prev; fi
mv "${OSV_STAGE}" /data/scanner-cache/osv
rm -rf /data/scanner-cache/osv.prev
'@

& docker run --rm `
    --user winhood `
    --cap-drop ALL `
    --security-opt no-new-privileges:true `
    -e GRYPE_DB_CACHE_DIR=/data/scanner-cache/grype `
    -e GRYPE_DB_AUTO_UPDATE=true `
    -e WINHOOD_OSV_DB_DIR=/data/scanner-cache/osv `
    -e "OSV_ECOSYSTEMS=$osvEcosystems" `
    -e "DB_TTL_DAYS=$dbTtlDays" `
    -v "${volumeName}:/data/scanner-cache" `
    winhood-scanner-worker:4.4.0 `
    bash -c $updateCmd

if ($LASTEXITCODE -ne 0) {
    Write-Error "[WinHood Scanner DB] Falha ao atualizar bases offline (codigo $LASTEXITCODE)."
    exit 1
}

Write-Host "[WinHood Scanner DB] Bases offline do Grype e OSV-Scanner atualizadas, validadas (SHA-256) e instaladas atomicamente em $volumeName." -ForegroundColor Green
