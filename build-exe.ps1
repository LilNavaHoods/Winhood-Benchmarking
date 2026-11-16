# WinHood Benchmarking — Automated Windows Desktop .EXE & Inno Setup Builder (PowerShell)
$ErrorActionPreference = "Stop"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "ERRO: Node.js 20+ nao encontrado no PATH. Instale o Node.js LTS antes de prosseguir."
    exit 1
}

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Error "ERRO: npm nao encontrado no PATH. Verifique a instalacao do Node.js."
    exit 1
}

if (-not (Test-Path "package.json") -or -not (Test-Path "package-lock.json")) {
    Write-Error "ERRO: package.json ou package-lock.json ausente na raiz do repositorio."
    exit 1
}

$pkg = Get-Content "package.json" -Raw | ConvertFrom-Json
$lock = Get-Content "package-lock.json" -Raw | ConvertFrom-Json

if ($pkg.name -ne $lock.name -or $pkg.version -ne $lock.version) {
    Write-Error "ERRO DE INTEGRIDADE: Divergencia entre package.json ($($pkg.name)@$($pkg.version)) e package-lock.json ($($lock.name)@$($lock.version))."
    exit 1
}

$appVersion = $pkg.version

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " WinHood Benchmarking v$appVersion — Windows x64 Desktop Builder" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

Write-Host "[1/5] Validando e instalando arvore de dependencias (npm ci com fallback automatico para npm install)..." -ForegroundColor Yellow
npm ci
if ($LASTEXITCODE -ne 0) {
    Write-Warning "AVISO: npm ci retornou codigo $LASTEXITCODE (sincronizando binarios Electron/Windows via npm install)..."
    npm install
    if ($LASTEXITCODE -ne 0) {
        Write-Error "ERRO: Falha ao instalar dependencias com npm install."
        exit $LASTEXITCODE
    }
}

Write-Host "[2/5] Compilando frontend Vite + bundle desktop (npm run desktop:compile)..." -ForegroundColor Yellow
npm run desktop:compile
if ($LASTEXITCODE -ne 0) {
    Write-Error "ERRO: Falha na compilacao do bundle desktop (npm run desktop:compile)."
    exit $LASTEXITCODE
}

Write-Host "[3/5] Gerando diretorio desempacotado Windows x64 (npm run pack:win)..." -ForegroundColor Yellow
npm run pack:win
if ($LASTEXITCODE -ne 0) {
    Write-Error "ERRO: Falha no empacotamento Electron Windows x64 (npm run pack:win)."
    exit $LASTEXITCODE
}

$unpackedDir = Join-Path $PSScriptRoot "release-windows\win-unpacked"
if (-not (Test-Path $unpackedDir)) {
    Write-Error "ERRO: Diretorio esperado '$unpackedDir' nao foi gerado pelo electron-builder."
    exit 1
}

Write-Host "[4/5] Localizando compilador Inno Setup 6 (ISCC.exe)..." -ForegroundColor Yellow
$candidateIsccPaths = @()
$isccCmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if ($isccCmd) {
    $candidateIsccPaths += $isccCmd.Source
}
if (${env:ProgramFiles(x86)}) {
    $candidateIsccPaths += Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
}
if ($env:ProgramFiles) {
    $candidateIsccPaths += Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"
}
if ($env:LOCALAPPDATA) {
    $candidateIsccPaths += Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"
}

$isccPath = $candidateIsccPaths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $isccPath) {
    Write-Error "ERRO: Inno Setup 6 (ISCC.exe) nao encontrado no PATH nem nos diretorios padrao do Windows."
    exit 1
}

Write-Host "[5/5] Compilando instalador Inno Setup via '$isccPath'..." -ForegroundColor Yellow
& $isccPath "/DMyAppVersion=$appVersion" "installer\WinHoodBenchmarking.iss"
if ($LASTEXITCODE -ne 0) {
    Write-Error "ERRO: Falha ao compilar installer\WinHoodBenchmarking.iss com ISCC.exe."
    exit $LASTEXITCODE
}

$expectedSetupExe = Join-Path $PSScriptRoot "release-windows\installer\WinHood-Benchmarking-Setup.exe"
if (-not (Test-Path $expectedSetupExe)) {
    Write-Error "ERRO: Instalador final '$expectedSetupExe' nao foi encontrado apos a compilacao."
    exit 1
}

Write-Host "Concluido com sucesso! Instalador oficial gerado em: $expectedSetupExe" -ForegroundColor Green
