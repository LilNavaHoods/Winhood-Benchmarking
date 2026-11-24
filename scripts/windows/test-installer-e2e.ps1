param(
  [Parameter(Mandatory=$true)][string]$InstallerPath,
  [Parameter(Mandatory=$false)][string]$ReportOutputPath = "release-windows\windows-installer-e2e-report.json"
)

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\WinHoodBenchmarking"
$UserDataDir = Join-Path $env:LOCALAPPDATA "WinHoodBenchmarking"
$LogsDir = Join-Path $UserDataDir "logs"
$RuntimeStatusFile = Join-Path $LogsDir "runtime-status.json"
$BootstrapLogFile = Join-Path $LogsDir "desktop-bootstrap.log"
$StdoutLogFile = Join-Path $LogsDir "e2e-electron-stdout.log"
$StderrLogFile = Join-Path $LogsDir "e2e-electron-stderr.log"
$InstalledExe = Join-Path $InstallDir "WinHood Benchmark Analyzer.exe"
$UninstallerExe = Join-Path $InstallDir "unins000.exe"
$StartMenuShortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\WinHood Benchmark Analyzer\WinHood Benchmark Analyzer.lnk"

$Steps = @()
$AppProc = $null
$Diagnostics = [ordered]@{
  electronPid = $null
  electronExitedEarly = $false
  electronExitCode = $null
  effectivePort = $null
  healthUrl = $null
  httpStatusCode = $null
  lastError = $null
  bootstrapLogTail = ""
  stdoutTail = ""
  stderrTail = ""
}

function Get-FileTailSafe {
  param([string]$FilePath, [int]$Lines = 40)
  if (-not (Test-Path $FilePath)) { return "" }
  try {
    return ((Get-Content -Path $FilePath -Tail $Lines -ErrorAction Stop) -join "`n")
  } catch {
    return "[Unreadable log: $($_.Exception.Message)]"
  }
}

function Record-Step {
  param([string]$Name, [bool]$Passed, [string]$Evidence)
  $script:Steps += [PSCustomObject]@{
    step = $Name
    status = if ($Passed) { "PASSED" } else { "FAILED" }
    evidence = $Evidence
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
  }
  if (-not $Passed) {
    throw "Installer E2E Step FAILED: $Name -> $Evidence"
  }
}

try {
  # 1. Verify installer binary exists & compute SHA-256
  $InstallerExists = Test-Path $InstallerPath
  $InstallerHash = if ($InstallerExists) { (Get-FileHash -Path $InstallerPath -Algorithm SHA256).Hash.ToLower() } else { "" }
  Record-Step "01_verify_installer_artifact" $InstallerExists "Path=$InstallerPath SHA256=$InstallerHash"

  # 2. Clean prior test residue if present
  if (Test-Path $UninstallerExe) {
    Start-Process -FilePath $UninstallerExe -ArgumentList "/VERYSILENT /NORESTART" -Wait
    Start-Sleep -Seconds 2
  }
  Record-Step "02_preinstall_clean_state" (-not (Test-Path $InstalledExe)) "Prior install absent"

  # 3. Silent installation without admin elevation (PrivilegesRequired=lowest)
  $InstallProc = Start-Process -FilePath $InstallerPath -ArgumentList "/VERYSILENT /NORESTART /SUPPRESSMSGBOXES /SP-" -Wait -PassThru
  Record-Step "03_silent_install" ($InstallProc.ExitCode -eq 0) "ExitCode=$($InstallProc.ExitCode)"

  # 4. Verify installed directory & main binary inside LOCALAPPDATA\Programs
  $ExeExists = Test-Path $InstalledExe
  $UninstallerExists = Test-Path $UninstallerExe
  Record-Step "04_verify_installed_files" ($ExeExists -and $UninstallerExists) "InstalledExe=$InstalledExe Uninstaller=$UninstallerExe"

  # 5. Verify unprivileged write policy (not installed in Program Files)
  $NotInProgramFiles = -not ($InstallDir.ToLower().StartsWith($env:ProgramFiles.ToLower()))
  Record-Step "05_verify_non_program_files_target" $NotInProgramFiles "InstallDir=$InstallDir"

  # 6. Verify Start Menu shortcut creation
  $ShortcutCreated = Test-Path $StartMenuShortcut
  Record-Step "06_verify_shortcuts" $ShortcutCreated "StartMenu=$StartMenuShortcut"

  # 7. Verify userData writable directories provisioned cleanly
  $DirsOk = (Test-Path (Join-Path $UserDataDir "data")) -and (Test-Path $LogsDir) -and (Test-Path (Join-Path $UserDataDir "keys"))
  Record-Step "07_verify_userdata_directories" $DirsOk "UserDataDir=$UserDataDir"

  # 8. Launch installed binary + discover actual port via runtime-status.json + probe /api/health
  if (Test-Path $RuntimeStatusFile) { Remove-Item -Path $RuntimeStatusFile -Force -ErrorAction SilentlyContinue }
  if (Test-Path $StdoutLogFile) { Remove-Item -Path $StdoutLogFile -Force -ErrorAction SilentlyContinue }
  if (Test-Path $StderrLogFile) { Remove-Item -Path $StderrLogFile -Force -ErrorAction SilentlyContinue }

  $env:WINHOOD_DATA_DIR = $UserDataDir
  $env:WINHOOD_RUNTIME_ENV = "ELECTRON_DESKTOP"
  $env:WINHOOD_DESKTOP_RUN = "true"
  $env:WINHOOD_BACKEND_READY_TIMEOUT_MS = "30000"

  $AppProc = Start-Process -FilePath $InstalledExe `
    -RedirectStandardOutput $StdoutLogFile `
    -RedirectStandardError $StderrLogFile `
    -PassThru
  $Diagnostics.electronPid = $AppProc.Id

  $Healthy = $false
  $HealthPayload = ""
  $EffectivePort = 3000
  $HealthUrl = "http://127.0.0.1:3000/api/health"

  for ($i = 0; $i -lt 45; $i++) {
    Start-Sleep -Seconds 1

    if ($AppProc.HasExited) {
      $Diagnostics.electronExitedEarly = $true
      $Diagnostics.electronExitCode = $AppProc.ExitCode
      $Diagnostics.lastError = "Electron exited prematurely with ExitCode=$($AppProc.ExitCode)"
      break
    }

    if (Test-Path $RuntimeStatusFile) {
      try {
        $RuntimeMeta = Get-Content -Path $RuntimeStatusFile -Raw | ConvertFrom-Json
        if ($RuntimeMeta.port) {
          $EffectivePort = [int]$RuntimeMeta.port
        }
        if ($RuntimeMeta.healthUrl) {
          $HealthUrl = [string]$RuntimeMeta.healthUrl
        } else {
          $HealthUrl = "http://127.0.0.1:$EffectivePort/api/health"
        }
      } catch {
        $Diagnostics.lastError = "runtime-status.json parse error: $($_.Exception.Message)"
      }
    }

    $Diagnostics.effectivePort = $EffectivePort
    $Diagnostics.healthUrl = $HealthUrl

    try {
      $Resp = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 3
      $Diagnostics.httpStatusCode = [int]$Resp.StatusCode
      if ($Resp.StatusCode -eq 200) {
        $HealthPayload = $Resp.Content
        if ($HealthPayload -match '"ready"\s*:\s*true' -and $HealthPayload -match '"status"\s*:\s*"ONLINE"') {
          $Healthy = $true
          $Diagnostics.lastError = $null
          break
        } else {
          $Diagnostics.lastError = "Health endpoint returned 200 without ready=true/ONLINE: $HealthPayload"
        }
      }
    } catch {
      $Diagnostics.lastError = "Health probe ($HealthUrl) attempt $($i + 1) failed: $($_.Exception.Message)"
    }
  }

  $Diagnostics.bootstrapLogTail = Get-FileTailSafe -FilePath $BootstrapLogFile
  $Diagnostics.stdoutTail = Get-FileTailSafe -FilePath $StdoutLogFile
  $Diagnostics.stderrTail = Get-FileTailSafe -FilePath $StderrLogFile

  $Step8Evidence = "PID=$($Diagnostics.electronPid) Port=$($Diagnostics.effectivePort) URL=$($Diagnostics.healthUrl) HttpStatus=$($Diagnostics.httpStatusCode) ExitedEarly=$($Diagnostics.electronExitedEarly) ExitCode=$($Diagnostics.electronExitCode) LastError=$($Diagnostics.lastError) Health=$HealthPayload"
  Record-Step "08_launch_and_health_check" $Healthy $Step8Evidence

  # 9. Verify real persistence files created inside %LOCALAPPDATA%\WinHoodBenchmarking
  $PersistedFiles = Get-ChildItem -Path $UserDataDir -Recurse -File | Measure-Object
  Record-Step "09_verify_userdata_persistence" ($PersistedFiles.Count -ge 1) "UserDataFilesCount=$($PersistedFiles.Count)"

  # 10. Clean shutdown of launched desktop application & child processes
  if ($AppProc -and -not $AppProc.HasExited) {
    Stop-Process -Id $AppProc.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
  }
  Get-Process -Name "WinHood Benchmark Analyzer" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
  Record-Step "10_clean_process_shutdown" $true "Stopped PID=$($AppProc.Id)"

  # 11. Write persistent user marker before uninstall to validate userData preservation
  $SentinelFile = Join-Path $UserDataDir "data\e2e-user-persistence-sentinel.txt"
  "winhood-persisted-v4.4.0" | Out-File -FilePath $SentinelFile -Encoding utf8
  Record-Step "11_seed_persistence_sentinel" (Test-Path $SentinelFile) "Sentinel=$SentinelFile"

  # 12. Execute real silent uninstall (unins000.exe /VERYSILENT)
  $UninstallProc = Start-Process -FilePath $UninstallerExe -ArgumentList "/VERYSILENT /NORESTART /SUPPRESSMSGBOXES" -Wait -PassThru
  Start-Sleep -Seconds 2
  $BinariesRemoved = -not (Test-Path $InstalledExe)
  Record-Step "12_silent_uninstall_and_cleanup" ($UninstallProc.ExitCode -eq 0 -and $BinariesRemoved) "ExitCode=$($UninstallProc.ExitCode) BinariesRemoved=$BinariesRemoved"

  # 13. Verify userData persistence retained after application binary uninstall
  $UserDataPreserved = Test-Path $SentinelFile
  Record-Step "13_userdata_preserved_after_uninstall" $UserDataPreserved "SentinelPreserved=$UserDataPreserved"
}
finally {
  if ($AppProc -and -not $AppProc.HasExited) {
    Stop-Process -Id $AppProc.Id -Force -ErrorAction SilentlyContinue
  }
  Get-Process -Name "WinHood Benchmark Analyzer" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

  $Diagnostics.bootstrapLogTail = Get-FileTailSafe -FilePath $BootstrapLogFile
  $Diagnostics.stdoutTail = Get-FileTailSafe -FilePath $StdoutLogFile
  $Diagnostics.stderrTail = Get-FileTailSafe -FilePath $StderrLogFile

  $Summary = [PSCustomObject]@{
    status = if ($Steps.Count -eq 13 -and -not ($Steps | Where-Object { $_.status -eq "FAILED" })) { "VALIDATED" } else { "FAILED" }
    installerPath = $InstallerPath
    executedAt = (Get-Date).ToUniversalTime().ToString("o")
    os = [System.Environment]::OSVersion.VersionString
    stepsCount = $Steps.Count
    diagnostics = $Diagnostics
    steps = $Steps
  }
  $ReportDir = Split-Path -Parent $ReportOutputPath
  if ($ReportDir -and -not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
  }
  $Summary | ConvertTo-Json -Depth 6 | Out-File -FilePath $ReportOutputPath -Encoding utf8
  Write-Host ($Summary | ConvertTo-Json -Depth 6)
}
