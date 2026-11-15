@echo off
SETLOCAL EnableDelayedExpansion
TITLE WinHood Benchmark Analyzer v4.5.0 — Desktop Launcher

echo ============================================================================
echo   WinHood Benchmark ^& Quality Analyzer v4.5.0 — Inicializador Local Windows
echo ============================================================================

IF EXIST "%~dp0release\win-unpacked\WinHood Benchmark Analyzer.exe" (
    echo [INFO] Iniciando executavel nativo empacotado...
    START "" "%~dp0release\win-unpacked\WinHood Benchmark Analyzer.exe"
    EXIT /B 0
)

WHERE node >NUL 2>NUL
IF %ERRORLEVEL% NEQ 0 (
    echo [ERRO] Node.js nao encontrado no PATH. Instale o Node.js 20+ LTS.
    PAUSE
    EXIT /B 1
)

IF NOT EXIST "%~dp0node_modules" (
    echo [1/3] Instalando dependencias do projeto...
    CALL npm install
)

IF NOT EXIST "%~dp0dist-desktop\server.mjs" (
    echo [2/3] Compilando bundle Desktop ^(Vite + Express + Electron^)...
    CALL npm run desktop:compile
)

echo [3/3] Iniciando servidor local WinHood e abrindo interface...
SET NODE_ENV=production
SET WINHOOD_RUNTIME_ENV=LOCAL_PRODUCTION
SET PORT=3000
START "" cmd /c "timeout /t 2 /nobreak >nul && start http://127.0.0.1:3000"
node "%~dp0dist-desktop\server.mjs"
