#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$WithSonar
)

$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir
$EnvFile = Join-Path $RootDir '.env.docker'

function New-CryptographicHexSecret {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error '[WinHood Docker] Docker nao encontrado no PATH. Instale o Docker Desktop.'
    exit 1
}

if (-not (Test-Path $EnvFile)) {
    Write-Host "[WinHood Docker] Gerando .env.docker com segredo mestre criptografico (32 bytes)..." -ForegroundColor Cyan
    $secret = New-CryptographicHexSecret
    $content = @(
        'WINHOOD_PORT=3000'
        "WINHOOD_KEYSTORE_MASTER_SECRET=$secret"
        'WINHOOD_SONAR_DOCKER_IMAGE=sonarqube:25.1.0.102122-community'
    ) -join "`n"
    [System.IO.File]::WriteAllText($EnvFile, "$content`n", [System.Text.UTF8Encoding]::new($false))
}

$envMap = @{}
foreach ($line in Get-Content $EnvFile) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
    $idx = $trimmed.IndexOf('=')
    if ($idx -gt 0) {
        $k = $trimmed.Substring(0, $idx).Trim()
        $v = $trimmed.Substring($idx + 1).Trim()
        $envMap[$k] = $v
    }
}

$port = if ($envMap.ContainsKey('WINHOOD_PORT') -and $envMap['WINHOOD_PORT']) { $envMap['WINHOOD_PORT'] } else { '3000' }
$masterSecret = if ($envMap.ContainsKey('WINHOOD_KEYSTORE_MASTER_SECRET')) { $envMap['WINHOOD_KEYSTORE_MASTER_SECRET'] } else { '' }
if ($masterSecret.Length -lt 32) {
    Write-Error '[WinHood Docker] WINHOOD_KEYSTORE_MASTER_SECRET em .env.docker deve ter no minimo 32 caracteres.'
    exit 1
}

$composeArgs = @('compose', '--env-file', $EnvFile)
if ($WithSonar) {
    $composeArgs += @('--profile', 'sonar')
}
$composeArgs += @('up', '-d', '--build')

Write-Host "[WinHood Docker] Construindo e iniciando containers (127.0.0.1:$port)..." -ForegroundColor Cyan
Push-Location $RootDir
try {
    & docker @composeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose falhou com codigo $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

$healthUrl = "http://127.0.0.1:$port/api/health"
Write-Host "[WinHood Docker] Aguardando healthcheck em $healthUrl..." -ForegroundColor Cyan

$healthy = $false
for ($attempt = 1; $attempt -le 45; $attempt++) {
    try {
        $resp = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 3
        if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) {
            $healthy = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}

if (-not $healthy) {
    Write-Error '[WinHood Docker] Healthcheck nao respondeu no tempo limite. Execute: docker compose logs -f winhood'
    exit 1
}

Write-Host ""
Write-Host "WinHood Local-Web pronto em: http://localhost:$port" -ForegroundColor Green
if ($WithSonar) {
    Write-Host "SonarQube Local (perfil sonar): http://localhost:9000" -ForegroundColor Green
}
