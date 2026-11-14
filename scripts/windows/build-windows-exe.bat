@echo off
setlocal enabledelayedexpansion

title WinHood Enterprise - Build Reprodutivel Windows Desktop (.EXE / NSIS)
color 0A

echo ======================================================================
echo       WINHOOD ENTERPRISE - BUILD REPRODUTIVEL WINDOWS (.EXE / NSIS)
echo ======================================================================
echo.

where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERRO] npm nao encontrado no ambiente de build.
    exit /b 1
)

echo [1/4] Validando tipagem TypeScript (npm run lint)...
call npm run lint
if %errorlevel% neq 0 (
    echo [ERRO] Falha na validacao TypeScript. Build abortado.
    exit /b 1
)

echo [2/4] Executando suite de testes automatizados (npm test)...
call npm test
if %errorlevel% neq 0 (
    echo [ERRO] Falha nos testes automatizados. Build abortado.
    exit /b 1
)

echo [3/4] Compilando frontend Vite + bundles desktop (npm run build:desktop)...
call npm run build:desktop
if %errorlevel% neq 0 (
    echo [ERRO] Falha ao compilar artefatos desktop.
    exit /b 1
)

echo [4/4] Empacotando instalador NSIS e executavel portatil com electron-builder...
call npx electron-builder --config electron-builder.json --win nsis portable
if %errorlevel% neq 0 (
    echo [AVISO] electron-builder requer o pacote electron instalado nas devDependencies do ambiente de release.
    exit /b 1
)

echo ======================================================================
echo  [SUCESSO] Artefatos gerados em release-windows\ e manifesto SHA-256 em dist-desktop\build-manifest.json
echo ======================================================================
exit /b 0
