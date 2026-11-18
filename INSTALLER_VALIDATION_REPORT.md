# Relatório de Validação do Empacotamento Desktop e Instalador Windows (`INSTALLER_VALIDATION_REPORT.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + rebuild de artefatos finais
- **Ambiente local:** Container Linux (`linux x64`), `Node.js v22.23.2`
- **Ferramentas:** `vite@8.3.8`, `esbuild@0.28.2`, `scripts/build-desktop.mjs`, `src/desktop/desktop.test.ts`, `installer/WinHoodBenchmarking.iss`, `scripts/windows/test-installer-e2e.ps1`
- **Comandos executados localmente:** `npm run build:desktop` e `npm run test:desktop`
- **Estado de validação:** `PARTIALLY_VALIDATED` *(bundles desktop, manifesto SHA-256 e suíte de ciclo de vida Electron/porta/caminhos `VALIDATED` em Linux; compilação `ISCC.exe` e execução E2E do instalador `.exe` em Windows permanecem `NOT_VALIDATED` neste container)*

---

## 1. Artefatos Compilados e Verificados Localmente (`dist-desktop/build-manifest.json`)

Gerado em `2026-11-18T00:37:58.572Z` (`Node v22.23.2`, `linux x64`):

| Artefato | Tamanho (Bytes) | SHA-256 Verificado | Estado Local |
|---|---|---|---|
| `dist/index.html` | `1,851` | `811dd965625bfae6a0a4594c9741ce75447112b4a225717c489f4c159b3d88b7` | `VALIDATED` |
| `dist-desktop/server.mjs` | `1,690,196` | `0e748f1deb64339166db508c09f874eb3192881be8d4dedd327e3889e536ca0b` | `VALIDATED` |
| `dist-desktop/electron-main.mjs` | `1,700,427` | `3d97c6c75b3e66f0ae94e7ad2a3968ca36d12abd26942adb66895701f3f956ef` | `VALIDATED` |
| `dist-desktop/electron-preload.cjs` | `2,430` | `11da9a3b2dc6c5ebb4a4d57c61aa917140136565ae6fdbb33a97793f195c5932` | `VALIDATED` |

---

## 2. Testes Automatizados Desktop Executados (`npm run test:desktop` — 7/7 PASS)

1. `WinHoodPaths`: Criação da hierarquia por usuário (`data`, `logs`, `keys`, `reports`, `temp`, `backups`) e bloqueio estrito contra caminhos em `C:\Program Files`.
2. `Electron Preload Bridge`: Allowlist estrita de canais IPC e congelamento (`Object.freeze`) da superfície `window.winhoodDesktop`.
3. `Electron Main Security`: `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, `webSecurity: true` e validação de origem loopback (`127.0.0.1`).
4. `bootstrapWindowsDesktop`: Inicialização sequencial do servidor Express, sondagem `/api/health` e fallback automático quando a porta preferencial está ocupada.
5. `stripTrailingSlashes`: Normalização determinística em tempo linear.
6. Alinhamento de versão `4.4.0` e diretórios `release-windows` entre `package.json`, `package-lock.json`, `electron-builder.json`, `installer/WinHoodBenchmarking.iss` e `scripts/windows/build-exe.ps1`.
7. Ciclo de vida de animação (`prefers-reduced-motion` e `visibilityState`).

---

## 3. Etapas Exclusivas de Host Windows (`NOT_VALIDATED` no Container Linux)

| Etapa Windows | Script / Ferramenta Configurada | Estado Atual |
|---|---|---|
| Empacotamento Win32 Unpacked (`npm run pack:win`) | `electron-builder --config electron-builder.json --dir` | `NOT_VALIDATED` *(configurado no job `windows-desktop-validation`)* |
| Compilação do instalador `WinHood-Benchmarking-Setup.exe` | `ISCC.exe /DMyAppVersion=4.4.0 installer/WinHoodBenchmarking.iss` | `NOT_VALIDATED` *(requer runner/host Windows)* |
| Ciclo E2E de 13 passos (instalação silenciosa -> launch -> `/api/health` -> `%LOCALAPPDATA%` -> desinstalação -> preservação de `userData`) | `scripts/windows/test-installer-e2e.ps1` | `IMPLEMENTED` / `NOT_VALIDATED` *(aguarda execução em `windows-latest`)* |
| Assinatura Authenticode (`signtool.exe`) | Certificado corporativo `WINDOWS_PFX_BASE64` | `BLOCKED` *(depende de certificado externo de Code Signing)* |
