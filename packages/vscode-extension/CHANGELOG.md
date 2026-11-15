# Changelog — `winhood-vscode`

## [4.4.0] - 2026-11-15
### Adicionado
- Comando `Winhood: Analisar arquivo atual` (`winhood.analyzeCurrentFile`) populando o painel Problems com severidade, `CWE`, `OWASP Top 10`, linha e coluna.
- Comando `Winhood: Analisar workspace` (`winhood.analyzeWorkspace`) com avaliação completa de Quality Gate no Modo MQR.
- Hover Provider exibindo descrição, regra, remediação sugerida e referência ao `RULE_CATALOG.md`.
- CodeActionProvider (`Quick Fix`) para correções automáticas determinísticas (`eval()`, SQL concatenado, segredos hardcoded e tags `:latest` em `Dockerfile`).
- Item na barra de status com cores semafóricas correspondentes ao estado do gate (`APPROVED`, `APPROVED_WITH_RESERVATIONS`, `BLOCKED`, `INCONCLUSIVE`, `REJECTED`).
- Modo offline automático com fallback para o CLI embarcado do WinHood.
