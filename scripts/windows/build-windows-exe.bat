@echo off
setlocal enabledelayedexpansion

title WinHood Enterprise - Compilador de Executavel Windows .EXE
color 0A

echo ======================================================================
echo       WINHOOD ENTERPRISE - COMPILADOR DE EXECUTAVEL WINDOWS (.EXE)
echo ======================================================================
echo.
echo [*] Este script empacota a aplicacao completa em executavel nativo .exe
echo     com instalador NSIS para distribuicao no Windows.
echo.

where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERRO] npm nao encontrado. Verifique a instalacao do Node.js.
    pause
    exit /b 1
)

echo [1/3] Compilando frontend e modulos de alta performance (Vite Build)...
call npm run build
if %errorlevel% neq 0 (
    echo [ERRO] Falha ao compilar frontend.
    pause
    exit /b 1
)

echo.
echo [2/3] Instalando dependencias de empacotamento desktop Windows...
call npm install -D electron electron-builder --no-save

echo.
echo [3/3] Gerando instalador NSIS e executavel portavel WinHood.exe...
npx electron-builder --win nsis portable --config.win.target=nsis

echo.
echo ======================================================================
echo  [SUCESSO] Compilacao concluida!
echo  Os instaladores estao disponiveis no diretorio: dist/
echo  - WinHood-Setup-1.0.0.exe (Instalador NSIS para Windows)
echo  - WinHood-1.0.0.exe (Versao Portatil sem instalacao)
echo ======================================================================
echo.
pause
