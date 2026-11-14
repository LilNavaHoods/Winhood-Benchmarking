# Guia de Instalação e Execução no Windows 10 / 11

## 1. Modalidades de Distribuição no Windows
O **WinHood Benchmark Analyzer** oferece duas modalidades de execução no Windows 10/11 (x64):

1. **Instalador Oficial NSIS (`WinHood-Setup-<versão>-x64.exe`)**:
   - Permite escolher o diretório de instalação (por usuário em `%LOCALAPPDATA%\Programs\WinHood` ou por máquina com elevação UAC).
   - Cria atalhos na Área de Trabalho e no Menu Iniciar.
   - Registra desinstalador no Painel de Controle / Configurações do Windows preservando os dados do usuário (`deleteAppDataOnUninstall: false`).
2. **Executável Portátil (`WinHood-Portable-<versão>-x64.exe`)**:
   - Execução direta sem necessidade de instalação prévia.

## 2. Independência de Node.js Externo
No aplicativo Windows empacotado com Electron:
- O runtime Node.js está embutido no próprio binário do Electron.
- O processo principal (`electron-main.mjs`) inicia o backend Express embutido (`server.mjs`) em `127.0.0.1`.
- Subprocessos de análise e testes isolados (`SandboxExecutor.ts`) utilizam `resolveNodeRuntimeForSubprocess()`, acionando `process.execPath` com `ELECTRON_RUN_AS_NODE=1`.
- **O usuário final não precisa instalar Node.js, npm ou tsx no Windows.**

## 3. Diretórios de Dados do Usuário (`%APPDATA%\WinHood`)
Todos os arquivos graváveis residem exclusivamente no perfil do usuário (nunca em `C:\Program Files`):
- `%APPDATA%\WinHood\database\` — Banco de dados persistente com escrita atômica e checksum SHA-256.
- `%APPDATA%\WinHood\security\` — Metadados de autenticação, sessões e bootstrap administrativo.
- `%APPDATA%\WinHood\keys\` — Cofre de chaves criptográficas (protegido por DPAPI no Windows).
- `%APPDATA%\WinHood\reports\` — Relatórios exportados (JSON, SARIF 2.1.0, HTML, Markdown, CSV).
- `%APPDATA%\WinHood\sonar\` — Configurações e relatórios sincronizados do SonarCloud/SonarQube.
- `%APPDATA%\WinHood\cache\` — Cache imutável indexado por SHA-256.
- `%APPDATA%\WinHood\logs\` — Logs operacionais estruturados.
- `%LOCALAPPDATA%\WinHood\tools\` — Scanners opcionais baixados sob demanda.

## 4. Como Compilar o Instalador a partir do Código-Fonte
Em uma estação de build Windows (ou via GitHub Actions `windows-latest`):
```bat
npm ci
npm run lint
npm test
npm run build:desktop
scripts\windows\build-windows-exe.bat
```
Os artefatos finais são gerados em `release-windows\` e o manifesto de integridade SHA-256 em `dist-desktop\build-manifest.json`.
