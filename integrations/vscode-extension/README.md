# WinHood VS Code Extension

Connects Visual Studio Code to a running WinHood Benchmarking server or local desktop runtime (`http://localhost:3000`) via the open SARIF 2.1.0 REST API (`/api/analyze/sarif`), rendering inline diagnostics and live versioned Quality Gate status in the editor status bar.

## Build & Sideload
```bash
cd integrations/vscode-extension
npm install
npm run compile
```
Open this folder in VS Code and press `F5` (Extension Development Host), then run command **WinHood: Run Independent Audit & Evaluate Quality Gate**.
