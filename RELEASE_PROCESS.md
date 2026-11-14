# Processo de Build, Empacotamento Windows e Release Reprodutível

## 1. Pipeline de Build Desktop (`npm run build:desktop`)
O script `scripts/build-desktop.mjs` executa quatro etapas determinísticas:
1. **Frontend Vite Build**: Compila a interface React/TypeScript em `dist/` com code-splitting (`React.lazy`) e `ModuleErrorBoundary`.
2. **Bundle do Servidor (`dist-desktop/server.mjs`)**: Empacota `server.ts` e seus motores analíticos para Node 22 ESM.
3. **Bundle do Processo Principal Electron (`dist-desktop/electron-main.mjs`)**: Empacota `electron-main.ts` com inicialização sequencial e verificação de `/api/health`.
4. **Bundle da Ponte Preload (`dist-desktop/electron-preload.cjs`)**: Empacota `electron-preload.ts` com `contextBridge` e allowlist estrita de canais IPC.

Ao final, `scripts/build-desktop.mjs` valida a existência e o tamanho de todos os artefatos e gera `dist-desktop/build-manifest.json` com os hashes **SHA-256** de cada bundle.

## 2. Geração do Instalador NSIS e Portátil (`.exe`)
Com `electron-builder.json`:
- `npm run pack:win` — Gera o diretório desempacotado (`release-windows/win-unpacked`) para inspeção e smoke test.
- `npm run dist:win` — Gera:
  - `WinHood-Setup-<version>-x64.exe` (Instalador NSIS com seleção de diretório, atalhos e preservação de `%APPDATA%\WinHood` na desinstalação/atualização).
  - `WinHood-Portable-<version>-x64.exe` (Executável portátil autônomo).

## 3. Integração Contínua Multiplataforma (`.github/workflows/ci-multiplatform.yml`)
O workflow executa automaticamente em `ubuntu-latest` e `windows-latest`:
- `npm ci` (respeitando `package-lock.json`, sem `--no-save`).
- `npm run lint` (`tsc --noEmit`).
- `npm test` (suítes unitárias, segurança, SonarCloud Methodology e Windows Desktop Lifecycle).
- `npm run build:desktop` e publicação do artefato `build-manifest.json`.
