@echo off
setlocal enabledelayedexpansion

title WinHood Enterprise - Windows Desktop High Performance
color 0B

echo ======================================================================
echo           WINHOOD ENTERPRISE - WINDOWS DESKTOP LAUNCHER
echo ======================================================================
echo.
echo [*] Verificando ambiente Node.js na maquina...
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERRO] Node.js nao foi detectado no PATH do Windows.
    echo Por favor instale o Node.js v20+ em https://nodejs.org
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('node -v') do set NODE_VERSION=%%v
echo [*] Node.js detectado: !NODE_VERSION!

echo [*] Configurando Prioridade de Processamento ALTA (High CPU Priority)...
echo [*] Ativando Worker Threads de Alto Rendimento para Testes Pesados...

set NODE_ENV=production
set WINHOOD_DESKTOP_RUN=true
set UV_THREADPOOL_SIZE=16

:: Inicia o servidor WinHood com prioridade alta na maquina Windows
start "WinHood Engine Server" /high cmd /c "npm run start"

echo.
echo [*] Aguardando inicializacao do servidor WinHood em http://localhost:3000...
timeout /t 3 /nobreak >nul

echo [*] Abrindo aplicacao na interface de alta resolucao...
start http://localhost:3000

echo.
echo ======================================================================
echo  [OK] WinHood Enterprise esta em execucao!
echo  Interface: http://localhost:3000
echo  Para SonarQube Docker: docker run -d -p 9000:9000 sonarqube:latest
echo ======================================================================
echo.
pause
