# Relatório de Validação E2E do Instalador Windows e Runtime Desktop (`WINDOWS_INSTALLER_E2E_REPORT.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + script E2E de 13 passos e CI multiplataforma
- **Ambiente local atual:** Container Linux (`linux x64`), `Node.js v22.23.2`
- **Arquivos principais:** `scripts/build-desktop.mjs`, `electron-main.ts`, `electron-preload.ts`, `src/storage/AppPaths.ts`, `installer/WinHoodBenchmarking.iss`, `scripts/windows/test-installer-e2e.ps1`, `.github/workflows/ci-multiplatform.yml`
- **Comandos executados localmente:** `npm run build:desktop` e `npm run test:desktop` (`7/7 PASS`)
- **Estado de validação:** `PARTIALLY_VALIDATED` *(compilação dos bundles desktop, manifesto SHA-256 e suíte de ciclo de vida Electron/porta/caminhos `VALIDATED` em Linux; compilação `ISCC.exe` e execução real dos 13 passos de `test-installer-e2e.ps1` em Windows permanecem `NOT_VALIDATED` localmente)*

---

## 1. O Que Foi Validado no Ambiente Atual (Linux Container)

| Verificação | Comando Executado | Resultado Real | Estado Oficial |
|---|---|---|---|
| **Build completo Frontend + Backend + Electron Main + Preload** | `npm run build:desktop` | Gerados `dist/index.html` (`1,851 B`), `dist-desktop/server.mjs` (`1,690,196 B`), `dist-desktop/electron-main.mjs` (`1,700,427 B`), `dist-desktop/electron-preload.cjs` (`2,430 B`) e `dist-desktop/build-manifest.json`. | `VALIDATED` |
| **Isolamento de diretórios por usuário (`WinHoodPaths`)** | `npm run test:desktop` (Subteste 1) | Cria `data`, `logs`, `keys`, `reports`, `temp`, `backups` no perfil do usuário e lança erro se o caminho apontar para `C:\Program Files`. | `VALIDATED` |
| **Hardening IPC & Preload (`electron-preload.ts` / `electron-main.ts`)** | `npm run test:desktop` (Subtestes 2 & 3) | `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, `webSecurity: true`, allowlist de canais IPC e verificação de sender loopback. | `VALIDATED` |
| **Inicialização sequencial e fallback de porta ocupada** | `npm run test:desktop` (Subteste 4) | `bootstrapWindowsDesktop` inicia Express em `127.0.0.1`, valida `/api/health` e faz fallback automático quando a porta preferencial está ocupada. | `VALIDATED` |
| **Alinhamento de versão `4.4.0` e scripts de instalador** | `npm run test:desktop` (Subteste 6) | `package.json`, `package-lock.json`, `electron-builder.json`, `installer/WinHoodBenchmarking.iss` e `scripts/windows/build-exe.ps1` 100% sincronizados. | `VALIDATED` |

---

## 2. Protocolo E2E de 13 Passos do Instalador Windows (`scripts/windows/test-installer-e2e.ps1`)

Integrado ao job `windows-desktop-validation` (`runs-on: windows-latest`) em `.github/workflows/ci-multiplatform.yml` (linhas 240–245):

| Passo | Identificador em `test-installer-e2e.ps1` | Verificação Real no Windows | Estado neste Container Linux |
|---|---|---|---|
| **01** | `01_verify_installer_artifact` | Confirma existência de `release-windows\installer\WinHood-Benchmarking-Setup.exe` e calcula SHA-256. | `NOT_VALIDATED` |
| **02** | `02_preinstall_clean_state` | Remove instalação prévia se existir e confirma estado limpo. | `NOT_VALIDATED` |
| **03** | `03_silent_install` | Executa instalador com `/VERYSILENT /NORESTART /SUPPRESSMSGBOXES /SP-` sem exigir privilégio de Administrador (`PrivilegesRequired=lowest`) e valida `ExitCode == 0`. | `NOT_VALIDATED` |
| **04** | `04_verify_installed_files` | Verifica `WinHood Benchmark Analyzer.exe` e `unins000.exe` em `%LOCALAPPDATA%\Programs\WinHoodBenchmarking`. | `NOT_VALIDATED` |
| **05** | `05_verify_non_program_files_target` | Confirma que a instalação não reside em `C:\Program Files`. | `NOT_VALIDATED` |
| **06** | `06_verify_shortcuts` | Confirma criação do atalho no Menu Iniciar (`%APPDATA%\Microsoft\Windows\Start Menu\Programs\...`). | `NOT_VALIDATED` |
| **07** | `07_verify_userdata_directories` | Verifica criação dos diretórios `data`, `logs` e `keys` em `%LOCALAPPDATA%\WinHoodBenchmarking`. | `NOT_VALIDATED` |
| **08** | `08_launch_and_health_check` | Inicia o executável instalado e consulta `http://127.0.0.1:3000/api/health` até receber `"ready":true` (`HTTP 200`). | `NOT_VALIDATED` |
| **09** | `09_verify_userdata_persistence` | Verifica arquivos persistidos dentro de `%LOCALAPPDATA%\WinHoodBenchmarking`. | `NOT_VALIDATED` |
| **10** | `10_clean_process_shutdown` | Encerra o processo da aplicação sem erros. | `NOT_VALIDATED` |
| **11** | `11_seed_persistence_sentinel` | Grava arquivo sentinela `data\e2e-user-persistence-sentinel.txt` nos dados do usuário antes da desinstalação. | `NOT_VALIDATED` |
| **12** | `12_silent_uninstall_and_cleanup` | Executa `unins000.exe /VERYSILENT /NORESTART /SUPPRESSMSGBOXES`, valida `ExitCode == 0` e confirma remoção do binário instalado. | `NOT_VALIDATED` |
| **13** | `13_userdata_preserved_after_uninstall` | Confirma que `data\e2e-user-persistence-sentinel.txt` em `%LOCALAPPDATA%\WinHoodBenchmarking` foi preservado após a desinstalação do aplicativo. | `NOT_VALIDATED` |

> **Evidência gerada na CI Windows:** Ao executar no runner `windows-latest`, o script grava `release-windows/windows-installer-e2e-report.json` e publica o artefato `winhood-windows-desktop-and-installer`.
