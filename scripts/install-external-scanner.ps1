# WinHood — Provisionamento de Scanner Externo Compatível com SARIF 2.1.0 (PowerShell)
param(
  [string]$InstallDir = "$env:LOCALAPPDATA\SoftwareBenchmarkAnalyzer\tools\external-scanner",
  [int]$Port = 9000
)

Write-Host "[WinHood] Preparando diretorio de ferramentas em: $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Write-Host "[WinHood] Ambiente para ingestao SARIF 2.1.0 pronto (Porta local opcional: $Port)."
