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

Write-Host "[WinHood Scanner DB] Atualizando base offline do Grype no volume $volumeName..." -ForegroundColor Cyan
& docker run --rm `
    --user winhood `
    --cap-drop ALL `
    --security-opt no-new-privileges:true `
    -e GRYPE_DB_CACHE_DIR=/data/scanner-cache/grype `
    -e GRYPE_DB_AUTO_UPDATE=true `
    -v "${volumeName}:/data/scanner-cache" `
    winhood-scanner-worker:4.4.0 `
    /usr/local/bin/grype db update

if ($LASTEXITCODE -ne 0) {
    Write-Error "[WinHood Scanner DB] Falha ao atualizar base offline do Grype (codigo $LASTEXITCODE)."
    exit 1
}

Write-Host '[WinHood Scanner DB] Base offline do Grype atualizada com sucesso.' -ForegroundColor Green
Write-Host "[WinHood Scanner DB] Nota: para OSV-Scanner offline, copie dumps OSV locais para /data/scanner-cache/osv no volume $volumeName."
