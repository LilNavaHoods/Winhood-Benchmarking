# Relatório de Validação do Empacotamento Desktop e Instalador Windows (`INSTALLER_VALIDATION_REPORT.md`)

**Data de Execução:** 2026-11-17  
**Arquitetura Desktop:** Electron `45.3.3` + `electron-builder` `26.18.0` + Inno Setup (`installer/WinHoodBenchmarking.iss`)

---

## 1. Verificações Executadas e Confirmadas no Ambiente Atual (Linux Container)

| Item Verificado | Evidência / Artefato | Resultado | Classificação |
|---|---|---|---|
| **Compilação do Frontend React 19 (`dist/`)** | `vite build` (`dist/index.html` e bundles JS/CSS hashados) | Compilado sem erros | **VALIDADO** |
| **Compilação do Processo Principal Electron (`dist-desktop/electron-main.mjs`)** | `esbuild` bundle ESM Node 20 com inicialização sequencial do servidor local e isolamento de diretórios | Compilado e verificado | **VALIDADO** |
| **Compilação da Ponte Preload Segura (`dist-desktop/electron-preload.cjs`)** | `contextBridge.exposeInMainWorld('winhoodDesktop', ...)` com `contextIsolation: true` e `nodeIntegration: false` | Compilado e verificado | **VALIDADO** |
| **Compilação do Servidor Express Embarcado (`dist-desktop/server.mjs`)** | Servidor HTTP `127.0.0.1` com fallback dinâmico de porta e healthcheck `/api/health` | Compilado e verificado | **VALIDADO** |
| **Manifesto de Integridade SHA-256 (`dist-desktop/build-manifest.json`)** | Hashes SHA-256 gerados para `electron-main.mjs`, `electron-preload.cjs`, `server.mjs` e `dist/index.html` | Gerado e validado | **VALIDADO** |
| **Script Inno Setup (`installer/WinHoodBenchmarking.iss`)** | `PrivilegesRequired=lowest`, `PrivilegesRequiredOverridesAllowed=dialog`, `{autopf}\{#MyAppName}`, `{localappdata}\WinHoodBenchmarking`, `[UninstallDelete]` limpo | Sintaxe e diretivas verificadas | **VALIDADO** |
| **Isolamento de Dados do Usuário (`src/storage/AppPaths.ts`)** | Bloqueio estrito contra gravação em `C:\Program Files` ou diretório do binário; redirecionamento para `%LOCALAPPDATA%\WinHoodBenchmarking` e `%APPDATA%\WinHoodBenchmarking` | Testado em unidade | **VALIDADO** |

---

## 2. Limitações de Ambiente Declaradas (Requerem Host/VM Windows Real)

Em conformidade com a Lei Fundamental de Transparência e Zero Simulações:

| Etapa de Validação Windows Nativa | Motivo da Limitação neste Ambiente | Onde é Executada | Classificação Atual |
|---|---|---|---|
| **Compilação binária `.exe` pelo compilador `ISCC.exe` (Inno Setup 6)** | O ambiente de execução atual é um container Linux (`linux x64`), onde o binário Windows `ISCC.exe` não está presente nativamente. | Executado automaticamente no runner `windows-latest` do workflow `.github/workflows/ci-multiplatform.yml` (`build-and-verify-windows`). | **PARCIALMENTE VALIDADO** (Script `.iss` e bundles validados; compilação `.exe` delegada ao CI Windows) |
| **Instalação silenciosa (`/VERYSILENT`), atalhos do Menu Iniciar e desinstalação limpa em Windows 10/11** | Exige subsistema gráfico e registro nativo do Windows 10/11. | Validado no job `build-and-verify-windows` do GitHub Actions e em homologação em VM Windows 10/11 limpa. | **NÃO VALIDADO LOCALMENTE NO CONTAINER LINUX** |
| **Assinatura Digital Authenticode (`signtool.exe`)** | Depende de certificado Code Signing corporativo (`WINDOWS_PFX_BASE64`) provisionado no cofre de segredos do CI. | Executado quando o certificado é fornecido ao pipeline de release. | **PENDENTE DE CERTIFICADO EXTERNO** |
