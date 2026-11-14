# Diagnóstico e Solução de Problemas no Windows (Troubleshooting)

## 1. Porta 3000 Ocupada (`EADDRINUSE`)
- **Comportamento no Desktop (`ELECTRON_DESKTOP`)**:
  - Se a porta `3000` já estiver em uso por outro serviço local, `startServer()` captura `EADDRINUSE` e aloca automaticamente uma porta efêmera livre em `127.0.0.1`, repassando a URL efetiva (`http://127.0.0.1:<porta>`) para a `BrowserWindow` e para o health check.
- **Comportamento em Modo Web Local**:
  - Defina a variável `PORT=3005` antes de iniciar ou encerre o processo que ocupa a porta 3000 (`netstat -ano | findstr :3000`).

## 2. Primeiro Acesso e Bootstrap do Administrador Inicial
- Na primeira inicialização do WinHood, o arquivo de token de uso único `admin_bootstrap_token.txt` é gravado em:
  - **Windows Desktop**: `%APPDATA%\WinHood\security\admin_bootstrap_token.txt`
  - **Desenvolvimento Local**: `.winhood_data\security\admin_bootstrap_token.txt`
- Copie o token contido nesse arquivo para criar a conta administrativa inicial na tela de Bootstrap.

## 3. Falha ao Executar SonarScanner CLI no Windows (`.bat` / `.cmd`)
- No Windows, o executável do SonarScanner é distribuído como `sonar-scanner.bat`.
- O Node.js moderno bloqueia `spawn('sonar-scanner.bat', args, { shell: false })` com `EINVAL`.
- O módulo `SonarScannerExecutor.ts` resolve isso através de `buildPlatformSafeSpawnSpec()`, invocando `cmd.exe /d /s /c ""C:\caminho\sonar-scanner.bat" "arg1" "arg2""` com `windowsVerbatimArguments: true`, `shell: false` e validação estrita contra metacaracteres (`&`, `|`, `;`, `` ` ``, `$`, `>`, `<`).

## 4. Integridade do Banco de Dados e Recuperação Automática (`.bak`)
- Caso o computador seja desligado abruptamente, `PersistentDatabaseManager` valida o checksum SHA-256 do arquivo `winhood_persistent_db.json` na inicialização.
- Se detectar corrupção no arquivo principal, restaura automaticamente a partir do backup íntegro `winhood_persistent_db.json.bak` e registra o evento `DATABASE_RECOVERED_FROM_BACKUP` na trilha de auditoria.
