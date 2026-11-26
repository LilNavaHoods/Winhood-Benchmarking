#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$WithSonar,
    [switch]$NoBuild
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

function Set-EnvKeyInFile {
    param(
        [string]$Path,
        [string]$Key,
        [string]$Value
    )
    $lines = if (Test-Path $Path) { @(Get-Content $Path) } else { @() }
    $replaced = $false
    $updated = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        if (-not $replaced -and $line -match "^$([regex]::Escape($Key))=") {
            $updated.Add("$Key=$Value")
            $replaced = $true
        } else {
            $updated.Add($line)
        }
    }
    if (-not $replaced) {
        $updated.Add("$Key=$Value")
    }
    $content = ($updated -join "`n") + "`n"
    [System.IO.File]::WriteAllText($Path, $content, [System.Text.UTF8Encoding]::new($false))
}

# 1. Pré-requisitos Docker
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error '[WinHood Docker] Comando "docker" nao encontrado no PATH. Instale o Docker Desktop: https://docs.docker.com/get-docker/'
    exit 1
}

& docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Error '[WinHood Docker] O Docker Engine/Desktop nao esta em execucao. Inicie o Docker Desktop e tente novamente.'
    exit 1
}

& docker compose version *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Error '[WinHood Docker] Docker Compose v2 ("docker compose") nao encontrado. Atualize o Docker Desktop.'
    exit 1
}

# 2. Preparação segura e não-destrutiva do .env.docker
if (-not (Test-Path $EnvFile)) {
    Write-Host '[WinHood Docker] Criando .env.docker com segredos criptograficos aleatorios (32 bytes)...' -ForegroundColor Cyan
    $secret = New-CryptographicHexSecret
    $workerToken = New-CryptographicHexSecret
    $content = @(
        '# Gerado automaticamente por scripts/docker-up.ps1 (nao versione este arquivo)'
        'WINHOOD_PORT=3000'
        "WINHOOD_KEYSTORE_MASTER_SECRET=$secret"
        "WINHOOD_SCANNER_WORKER_TOKEN=$workerToken"
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

# 3. Validação de configuração sem sobrescrever customizações do usuário
$portRaw = if ($envMap.ContainsKey('WINHOOD_PORT') -and $envMap['WINHOOD_PORT']) { $envMap['WINHOOD_PORT'] } else { '3000' }
$portInt = 0
if (-not [int]::TryParse($portRaw, [ref]$portInt) -or $portInt -lt 1024 -or $portInt -gt 65535) {
    Write-Error "[WinHood Docker] WINHOOD_PORT invalido ('$portRaw'). Utilize uma porta entre 1024 e 65535."
    exit 1
}

$masterSecret = if ($envMap.ContainsKey('WINHOOD_KEYSTORE_MASTER_SECRET')) { $envMap['WINHOOD_KEYSTORE_MASTER_SECRET'] } else { '' }
if ([string]::IsNullOrWhiteSpace($masterSecret)) {
    Write-Host '[WinHood Docker] Preenchendo WINHOOD_KEYSTORE_MASTER_SECRET ausente em .env.docker...' -ForegroundColor Cyan
    $masterSecret = New-CryptographicHexSecret
    Set-EnvKeyInFile -Path $EnvFile -Key 'WINHOOD_KEYSTORE_MASTER_SECRET' -Value $masterSecret
}
if ($masterSecret.Length -lt 32) {
    Write-Error '[WinHood Docker] WINHOOD_KEYSTORE_MASTER_SECRET em .env.docker deve ter no minimo 32 caracteres.'
    exit 1
}

$workerTokenVal = if ($envMap.ContainsKey('WINHOOD_SCANNER_WORKER_TOKEN')) { $envMap['WINHOOD_SCANNER_WORKER_TOKEN'] } else { '' }
if ([string]::IsNullOrWhiteSpace($workerTokenVal)) {
    Write-Host '[WinHood Docker] Preenchendo WINHOOD_SCANNER_WORKER_TOKEN ausente em .env.docker...' -ForegroundColor Cyan
    $workerTokenVal = New-CryptographicHexSecret
    Set-EnvKeyInFile -Path $EnvFile -Key 'WINHOOD_SCANNER_WORKER_TOKEN' -Value $workerTokenVal
}
if ($workerTokenVal.Length -lt 32) {
    Write-Error '[WinHood Docker] WINHOOD_SCANNER_WORKER_TOKEN em .env.docker deve ter no minimo 32 caracteres.'
    exit 1
}

# 4. Validação do manifesto Compose e inicialização dos serviços
$baseComposeArgs = @('compose', '--env-file', $EnvFile)
if ($WithSonar) {
    $baseComposeArgs += @('--profile', 'sonar')
}

$upArgs = $baseComposeArgs + @('up', '-d')
if (-not $NoBuild) {
    $upArgs += '--build'
}

Write-Host "[WinHood Docker] Validando docker-compose.yml e iniciando containers (127.0.0.1:$portInt)..." -ForegroundColor Cyan
Push-Location $RootDir
try {
    & docker @($baseComposeArgs + @('config', '-q'))
    if ($LASTEXITCODE -ne 0) {
        throw "Validacao de docker-compose.yml falhou com codigo $LASTEXITCODE"
    }
    & docker @upArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose up falhou com codigo $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

# 5. Aguarda healthchecks reais do backend e integração com o scanner worker
$healthUrl = "http://127.0.0.1:$portInt/api/health"
$capsUrl = "http://127.0.0.1:$portInt/api/scanner-worker/capabilities"
Write-Host "[WinHood Docker] Aguardando healthcheck em $healthUrl..." -ForegroundColor Cyan

$healthy = $false
for ($attempt = 1; $attempt -le 60; $attempt++) {
    try {
        $resp = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 4
        if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) {
            $healthy = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}

if (-not $healthy) {
    Write-Error '[WinHood Docker] Healthcheck nao respondeu no tempo limite. Execute: docker compose logs -f winhood winhood-scanner-worker'
    exit 1
}

$workerStatus = 'nao verificado'
try {
    $capsResp = Invoke-WebRequest -Uri $capsUrl -UseBasicParsing -TimeoutSec 10
    if ($capsResp.Content -match '"workerReachable"\s*:\s*true') {
        $workerStatus = 'conectado e autenticado'
    } else {
        $workerStatus = 'indisponivel (verifique logs do winhood-scanner-worker)'
    }
} catch {
    $workerStatus = 'nao verificado'
}

Write-Host ''
Write-Host '========================================================================' -ForegroundColor Green
Write-Host '  WinHood Benchmarking Local-Web esta pronto!' -ForegroundColor Green
Write-Host '========================================================================' -ForegroundColor Green
Write-Host "  Endereco Web:     http://localhost:$portInt" -ForegroundColor Green
Write-Host "  Scanner Worker:   $workerStatus" -ForegroundColor Cyan
if ($WithSonar) {
    Write-Host '  SonarQube Local:  http://localhost:9000' -ForegroundColor Green
}
Write-Host ''
Write-Host '  Comandos uteis:'
Write-Host '    Status:         docker compose ps'
Write-Host '    Logs:           docker compose logs -f'
Write-Host '    Reiniciar:      docker compose restart'
Write-Host '    Encerrar:       .\scripts\docker-down.ps1'
Write-Host '    Bases offline:  .\scripts\docker-update-scanner-dbs.ps1 (opcional: Grype)'
Write-Host '========================================================================' -ForegroundColor Green
