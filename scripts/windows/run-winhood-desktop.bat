@echo off
setlocal enabledelayedexpansion

title WinHood Enterprise - Windows Desktop Launcher (Sequential Health Check)
color 0B

echo ======================================================================
echo           WINHOOD ENTERPRISE - WINDOWS DESKTOP LAUNCHER
echo ======================================================================
echo.

:: Se existir o executavel empacotado (autonomo com runtime embutido), executa direto sem exigir Node externo
if exist "%~dp0..\..\release-windows\win-unpacked\WinHood Benchmark Analyzer.exe" (
    echo [*] Executavel autonomo detectado. Iniciando WinHood Desktop nativo...
    start "" "%~dp0..\..\release-windows\win-unpacked\WinHood Benchmark Analyzer.exe"
    exit /b 0
)

echo [*] Verificando ambiente Node.js local para modo de desenvolvimento...
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERRO] Node.js nao detectado no PATH e pacote autonomo ainda nao compilado.
    echo Execute o instalador WinHood-Setup.exe ou instale Node.js v20+ para modo dev.
    pause
    exit /b 1
)

set NODE_ENV=production
set WINHOOD_RUNTIME_ENV=ELECTRON_DESKTOP
set UV_THREADPOOL_SIZE=16

if not exist "%APPDATA%\WinHood" mkdir "%APPDATA%\WinHood"
set WINHOOD_DATA_DIR=%APPDATA%\WinHood

echo [*] Iniciando backend local em loopback 127.0.0.1:3000...
start "WinHood Engine Server" /min cmd /c "npm run start"

echo [*] Aguardando verificacao real de saude em http://127.0.0.1:3000/api/health...
set HEALTH_OK=0
for /L %%i in (1,1,30) do (
    if !HEALTH_OK! equ 0 (
        powershell -NoProfile -Command "try { $r = Invoke-RestMethod -Uri 'http://127.0.0.1:3000/api/health' -TimeoutSec 2; if ($r.status -eq 'ONLINE' -or $r.healthStatus -eq 'HEALTHY') { exit 0 } else { exit 1 } } catch { exit 1 }"
        if !errorlevel! equ 0 (
            set HEALTH_OK=1
        ) else (
            timeout /t 1 /nobreak >nul
        )
    )
)

if !HEALTH_OK! neq 1 (
    echo [ERRO] O backend nao respondeu ao health check em http://127.0.0.1:3000/api/health.
    echo Verifique os logs em %APPDATA%\WinHood\logs
    pause
    exit /b 1
)

echo [OK] Health check verificado (status=ONLINE). Abrindo interface...
start http://127.0.0.1:3000
exit /b 0
