# Integração com IDEs — WinHood Benchmarking (`IDE_INTEGRATION.md`)

Este documento descreve a arquitetura de integração do **WinHood Benchmarking** no fluxo diário do desenvolvedor dentro do editor de código, tendo o **VS Code** (`packages/vscode-extension`) como implementação de referência e suporte complementar para **JetBrains IDEs** (`integrations/jetbrains`).

---

## 1. Arquitetura da Extensão VS Code (`packages/vscode-extension`)

A extensão oficial `winhood-vscode` conecta o editor diretamente à API local/remota do WinHood ou, em **modo offline**, executa a CLI embarcada (`winhood-cli.ts`), mantendo paridade de regras e de Quality Gates entre o ambiente local e o pipeline de CI/CD.

### Funcionalidades Principais

1. **`Winhood: Analisar arquivo atual` (`winhood.analyzeCurrentFile`):**
   - Analisa instantaneamente o arquivo aberto no editor, populando o painel **Problems** do VS Code com severidade, identificador da regra, `CWE`, `OWASP Top 10`, linha e coluna exatas.
2. **`Winhood: Analisar workspace` (`winhood.analyzeWorkspace`):**
   - Executa a auditoria completa do workspace e atualiza o estado do Quality Gate na barra de status (`APPROVED`, `APPROVED_WITH_RESERVATIONS`, `BLOCKED`, `INCONCLUSIVE`, `REJECTED`).
3. **Hover Contextual Rico:**
   - Ao posicionar o cursor sobre uma linha com achado, exibe um card em Markdown contendo: descrição técnica, código da regra, classificação MQR, remediação recomendada e referência direta ao catálogo de regras (`RULE_CATALOG.md`).
4. **Code Actions Determinísticas (`Quick Fix`):**
   - Oferece correções automáticas determinísticas diretamente pelo menu de lâmpada (`Ctrl+.` / `Cmd+.`) para regras que possuem substituição segura de sintaxe (ex.: substituição de `eval()`, parametrização de consultas SQL concatenadas, remoção de credenciais hardcoded para variáveis de ambiente e endurecimento de instruções em `Dockerfile`).
5. **Status Bar Semafórica:**
   - Exibe o estado do gate com cores semânticas:
     - Verde: `APPROVED`
     - Amarelo: `APPROVED_WITH_RESERVATIONS`
     - Vermelho: `BLOCKED` / `REJECTED`
     - Cinza: `INCONCLUSIVE` / `NOT_MEASURED`
6. **Modo Offline Automático:**
   - Caso a API configurada em `winhood.apiBaseUrl` não esteja acessível, a extensão invoca automaticamente o motor CLI embarcado sem interromper o fluxo do desenvolvedor.

---

## 2. Configuração (`settings.json`)

```json
{
  "winhood.apiBaseUrl": "http://localhost:3000",
  "winhood.apiToken": "",
  "winhood.analysisProfile": "mqr-strict",
  "winhood.qualityGateId": "winhood-standard-v2",
  "winhood.offlineCliFallback": true
}
```
