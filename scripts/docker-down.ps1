#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$PurgeVolumes,
    [switch]$ConfirmDataLoss
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$EnvFile = Join-Path $RootDir '.env.docker'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error '[WinHood Docker] Comando "docker" nao encontrado no PATH.'
    exit 1
}

& docker compose version *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Error '[WinHood Docker] Docker Compose v2 nao encontrado.'
    exit 1
}

if ($PurgeVolumes -and -not $ConfirmDataLoss) {
    Write-Error '[WinHood Docker] ACAO DESTRUTIVA BLOQUEADA: -PurgeVolumes apaga projetos, cofre criptografado e historico. Use -PurgeVolumes -ConfirmDataLoss para confirmar.'
    exit 2
}

$composeArgs = @('compose', '--profile', 'sonar')
if (Test-Path $EnvFile) {
    $composeArgs += @('--env-file', $EnvFile)
}
$composeArgs += @('down', '--remove-orphans')
if ($PurgeVolumes) {
    $composeArgs += '-v'
    Write-Host '[WinHood Docker] Encerrando containers e REMOVENDO volumes persistentes...' -ForegroundColor Yellow
} else {
    Write-Host '[WinHood Docker] Encerrando containers (volumes persistentes serao preservados)...' -ForegroundColor Cyan
}

Push-Location $RootDir
try {
    & docker @composeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose down falhou com codigo $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

Write-Host '[WinHood Docker] Encerramento concluido.' -ForegroundColor Green
