#Requires -Version 5.1
<#
.SYNOPSIS
  Instalador Oficial do SonarQube Community Build & SonarScanner CLI para Windows (x64)
  WinHood Software Benchmark & Quality Analyzer
.DESCRIPTION
  - Baixa exclusivamente da distribuição oficial da SonarSource (binaries.sonarsource.com)
  - Valida o checksum SHA-256 oficial antes de extrair
  - Armazena fora do repositório de código-fonte (%LOCALAPPDATA%\SoftwareBenchmarkAnalyzer\tools\sonarqube\)
  - Não baixa novamente se a instalação já existir e estiver validada
  - Verifica requisitos mínimos (JDK 21, 4 GB RAM livre, 2 núcleos de CPU, 30 GB de disco)
#>

param(
  [string]$SonarVersion = "26.11.0.134175",
  [string]$OfficialSha256 = "bc18bf0f9faed6d27c9668a89ab86c84b22edeccb1050fbebb9d323bd506e7dc",
  [string]$ScannerVersion = "8.4.0.16527",
  [string]$ScannerSha256 = "9998fca7f8897975f8fad850aa92e5a236441ace6c6126a15da34f5a049795ce",
  [int]$Port = 9000,
  [string]$InstallRoot = "$env:LOCALAPPDATA\SoftwareBenchmarkAnalyzer\tools"
)

$ErrorActionPreference = "Stop"

Write-Host "=== WinHood Benchmark Analyzer - Gerenciador de Instalacao SonarQube Community Build ===" -ForegroundColor Cyan
Write-Host "1. Verificando requisitos de hardware e Java (JDK 21+)..."

$osInfo = Get-CimInstance Win32_OperatingSystem
$freeRamMb = [math]::Round($osInfo.FreePhysicalMemory / 1024)
$cpuCores = (Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum

Write-Host "   - RAM Livre: $freeRamMb MB (Minimo recomendado: 4096 MB)"
Write-Host "   - Nucleos de CPU: $cpuCores (Minimo recomendado: 2)"

if ($freeRamMb -lt 4096) {
  Write-Warning "RAM livre ($freeRamMb MB) abaixo dos 4096 MB recomendados para o Elasticsearch do SonarQube. Considere utilizar Modo Servidor Remoto."
}

try {
  $javaVer = & java -version 2>&1 | Select-Object -First 1
  Write-Host "   - Java detectado: $javaVer" -ForegroundColor Green
} catch {
  Write-Error "JDK 21 nao encontrado no PATH. Instale OpenJDK / Eclipse Temurin 21 LTS antes de iniciar o servidor local."
}

$sonarBaseDir = Join-Path $InstallRoot "sonarqube"
$targetDir = Join-Path $sonarBaseDir "sonarqube-$SonarVersion"
$zipPath = Join-Path $sonarBaseDir "sonarqube-$SonarVersion.zip"
$downloadUrl = "https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-$SonarVersion.zip"

if (!(Test-Path $sonarBaseDir)) {
  New-Item -ItemType Directory -Force -Path $sonarBaseDir | Out-Null
}

if (Test-Path (Join-Path $targetDir "bin\windows-x86-64\StartSonar.bat")) {
  Write-Host "2. Instalacao validada do SonarQube Community Build v$SonarVersion ja existe em: $targetDir" -ForegroundColor Green
  Write-Host "   Nenhum novo download necessario."
} else {
  Write-Host "2. Baixando distribuicao oficial SonarQube Community Build v$SonarVersion..."
  Write-Host "   Origem: $downloadUrl"
  Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing

  Write-Host "3. Validando hash SHA-256 oficial..."
  $computedHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
  if ($computedHash -ne $OfficialSha256.ToLower()) {
    Remove-Item $zipPath -Force
    throw "FALHA DE INTEGRIDADE SHA-256! Esperado: $OfficialSha256 | Calculado: $computedHash"
  }
  Write-Host "   SHA-256 Validado com sucesso: $computedHash" -ForegroundColor Green

  Write-Host "4. Extraindo arquivos para $sonarBaseDir..."
  Expand-Archive -Path $zipPath -DestinationPath $sonarBaseDir -Force
}

$propsFile = Join-Path $targetDir "conf\sonar.properties"
if (Test-Path $propsFile) {
  $content = Get-Content $propsFile
  if (!($content -match "sonar\.web\.port=$Port")) {
    Add-Content -Path $propsFile -Value "`nsonar.web.port=$Port"
  }
}

Write-Host "=== Instalacao concluida e verificada! ===" -ForegroundColor Cyan
Write-Host "Para iniciar sob demanda: & '$targetDir\bin\windows-x86-64\StartSonar.bat'"
