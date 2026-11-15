# WinHood Benchmarking v4.5.0 — Automated Windows Desktop .EXE Builder (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " WinHood Benchmarking v4.5.0 — Windows x64 Desktop Builder (.EXE)" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Error "Node.js 20+ nao encontrado no PATH. Instale o Node.js LTS antes de compilar."
    exit 1
}

Write-Host "[1/4] Instalando dependencias deterministicas..." -ForegroundColor Yellow
npm install

Write-Host "[2/4] Compilando frontend Vite + bundle desktop (server.mjs + electron-main.mjs)..." -ForegroundColor Yellow
npm run desktop:compile

Write-Host "[3/4] Empacotando executavel Windows x64 (NSIS + Portable .EXE) via electron-builder..." -ForegroundColor Yellow
npx electron-builder --win --x64

$isccPath = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (Test-Path $isccPath) {
    Write-Host "[4/4] Inno Setup 6 detectado! Gerando instalador corporativo via WinHoodBenchmarking.iss..." -ForegroundColor Green
    & $isccPath "installer\WinHoodBenchmarking.iss"
} else {
    Write-Host "[4/4] Pacotes NSIS Setup e Portable .EXE gerados com sucesso na pasta .\release\" -ForegroundColor Green
}

Write-Host "Concluido! Executaveis disponiveis em .\release\" -ForegroundColor Cyan
