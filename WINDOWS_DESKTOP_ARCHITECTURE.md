# Arquitetura Windows Desktop & Electron do WinHood

## 1. Fluxo Sequencial Determinístico de Inicialização
O processo principal do Electron (`electron-main.ts`) executa rigorosamente a seguinte sequência antes de exibir qualquer janela:

1. **Resolução de `userData`**:
   - Obtém `app.getPath('userData')` (`%APPDATA%\WinHood`) e valida com `isReadOnlyProgramFilesPath()` que o caminho não pertence a `Program Files` ou `Program Files (x86)`.
2. **Provisionamento de Diretórios (`ensureWinHoodDirectories`)**:
   - Garante a existência de `database/`, `security/`, `keys/`, `reports/`, `sonar/`, `cache/`, `logs/` e `isolated_artifacts/`.
3. **Inicialização do Backend Embutido (`startServer`)**:
   - Inicia o servidor HTTP Express estritamente em `127.0.0.1` na porta `3000`.
   - Caso a porta `3000` esteja ocupada no host Windows (`EADDRINUSE`), seleciona automaticamente uma porta dinâmica livre em `127.0.0.1`.
4. **Verificação Real de Saúde (`waitForBackendHealth`)**:
   - Realiza polling HTTP em `GET http://127.0.0.1:<porta>/api/health` até receber `status: "ONLINE"` e `ready: true`.
5. **Registro de Canais IPC Validados**:
   - Registra `winhood:get-runtime-info`, `winhood:get-backend-health` e `winhood:open-logs-folder`, validando `event.senderFrame.url` via `isAuthorizedLoopbackSender()`.
6. **Abertura da `BrowserWindow` Endurecida**:
   - Carrega `http://127.0.0.1:<porta>` e exibe a janela somente após o carregamento.
7. **Encerramento Limpo (`shutdownCleanly`)**:
   - Nos eventos `before-quit` e `window-all-closed`, encerra apenas o listener HTTP e os subprocessos próprios do WinHood, sem matar processos externos do usuário.

## 2. Controles de Segurança do Electron
`ELECTRON_SECURITY_WEB_PREFERENCES` impõe:
- `nodeIntegration: false`
- `contextIsolation: true`
- `sandbox: true`
- `webSecurity: true`
- `allowRunningInsecureContent: false`
- `preload`: `electron-preload.cjs` (ponte imutável via `contextBridge.exposeInMainWorld` com allowlist estrita de 3 canais).
- Bloqueio de `will-navigate` e `setWindowOpenHandler` para qualquer origem fora de `http://127.0.0.1:<porta>`.
