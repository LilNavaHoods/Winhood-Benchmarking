# WinHood — Exportador Silencioso de Relatorio SARIF 2.1.0 e Quality Gate (.PS1)
param(
  [string]$WorkspacePath = ".",
  [string]$GateId = "winhood-standard-v2",
  [string]$OutFile = "winhood-results.sarif"
)

npx tsx cli/winhood-cli.ts analyze --path $WorkspacePath --gate $GateId --format sarif --deterministic --out $OutFile
Write-Host "[WinHood] Relatorio SARIF 2.1.0 exportado em $OutFile"
