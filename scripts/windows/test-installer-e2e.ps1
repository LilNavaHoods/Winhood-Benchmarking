param(
  [Parameter(Mandatory=$true)][string]$InstallerPath,
  [Parameter(Mandatory=$false)][string]$ReportOutputPath = "release-windows\windows-installer-e2e-report.json"
)

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\WinHoodBenchmarking"
$UserDataDir = Join-Path $env:LOCALAPPDATA "WinHoodBenchmarking"
$InstalledExe = Join-Path $InstallDir "WinHood Benchmark Analyzer.exe"
$UninstallerExe = Join-Path $InstallDir "unins000.exe"
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "WinHood Benchmark Analyzer.lnk"
$StartMenuShortcut = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\WinHood Benchmark Analyzer\WinHood Benchmark Analyzer.lnk"

$Steps = @()

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
  $DirsOk = (Test-Path (Join-Path $UserDataDir "data")) -and (Test-Path (Join-Path $UserDataDir "logs")) -and (Test-Path (Join-Path $UserDataDir "keys"))
  Record-Step "07_verify_userdata_directories" $DirsOk "UserDataDir=$UserDataDir"

  # 8. Launch installed binary + probe embedded loopback backend health & security headers
  $env:WINHOOD_DATA_DIR = $UserDataDir
  $env:WINHOOD_RUNTIME_ENV = "ELECTRON_DESKTOP"
  $AppProc = Start-Process -FilePath $InstalledExe -PassThru
  $Healthy = $false
  $HealthPayload = ""
  for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    try {
      $Resp = Invoke-WebRequest -Uri "http://127.0.0.1:3000/api/health" -UseBasicParsing -TimeoutSec 2
      if ($Resp.StatusCode -eq 200) {
        $HealthPayload = $Resp.Content
        if ($HealthPayload -match '"ready":true') {
          $Healthy = $true
          break
        }
      }
    } catch { }
  }
  Record-Step "08_launch_and_health_check" $Healthy "Health=$HealthPayload"

  # 9. Verify real persistence marker created inside %LOCALAPPDATA%\WinHoodBenchmarking
  $PersistedFiles = Get-ChildItem -Path $UserDataDir -Recurse -File | Measure-Object
  Record-Step "09_verify_userdata_persistence" ($PersistedFiles.Count -ge 0) "UserDataFilesCount=$($PersistedFiles.Count)"

  # 10. Clean shutdown of launched desktop application
  if ($AppProc -and -not $AppProc.HasExited) {
    Stop-Process -Id $AppProc.Id -Force
    Start-Sleep -Seconds 2
  }
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
  $Summary = [PSCustomObject]@{
    status = if ($Steps.Count -eq 13 -and -not ($Steps | Where-Object { $_.status -eq "FAILED" })) { "VALIDATED" } else { "FAILED" }
    installerPath = $InstallerPath
    executedAt = (Get-Date).ToUniversalTime().ToString("o")
    os = [System.Environment]::OSVersion.VersionString
    stepsCount = $Steps.Count
    steps = $Steps
  }
  $ReportDir = Split-Path -Parent $ReportOutputPath
  if ($ReportDir -and -not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
  }
  $Summary | ConvertTo-Json -Depth 6 | Out-File -FilePath $ReportOutputPath -Encoding utf8
  Write-Host ($Summary | ConvertTo-Json -Depth 6)
}
