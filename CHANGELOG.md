# Changelog — WinHood Benchmarking (`CHANGELOG.md`)

Todas as mudanças notáveis da plataforma **WinHood Benchmarking** seguem **Versionamento Semântico (SemVer 2.0.0)** sem quebra dos contratos públicos existentes.

---

## [4.4.0] - 2026-11-15 — Iteração de Fechamento (Posicionamento Independente, IDE, CI/CD, Transparência e Relatórios Assinados)

### Posicionamento Independente & Renomeações (Bloco A)
- **Modo MQR (Modern Quality Regime) & Perfil de Qualidade Estrita:** Renomeado o antigo modo `"SonarQube MQR Mode"` para **`"Modo MQR (Modern Quality Regime)"`** e **`"Perfil de Qualidade Estrita"`**, mantendo 100% do comportamento funcional e retrocompatibilidade de chaves de configuração.
- **Documentação Neutra de Contratos:** Renomeados os documentos com prefixo legado `SONARQUBE_*` para `API_REFERENCE.md`, `IDE_INTEGRATION.md`, `EXTERNAL_INTEGRATION.md`, `MQR_METHODOLOGY.md` e `AUTONOMOUS_REMEDIATION.md`, descrevendo exclusivamente os contratos do WinHood e padrões abertos (**SARIF 2.1.0, CWE, OWASP Top 10, CVSS, CycloneDX 1.5, SPDX 2.3**).
- **Glossário Oficial (`GLOSSARY.md`):** Publicado glossário canônico definindo Modo MQR, Motor de Veracidade, Comparabilidade, Confiança da Evidência, Estados de Quality Gate e Trilha Criptográfica de Evidências.

### Extensão de IDE — VS Code MVP (Bloco B)
- **Novo pacote `packages/vscode-extension` (`winhood-vscode` v4.4.0):**
  - Comandos `Winhood: Analisar arquivo atual` (`winhood.analyzeCurrentFile`) e `Winhood: Analisar workspace` (`winhood.analyzeWorkspace`).
  - Hover contextual rico com descrição, regra, `CWE`, `OWASP Top 10`, remediação sugerida e link para `RULE_CATALOG.md`.
  - `CodeActionProvider` (`Quick Fix`) para correções automáticas determinísticas.
  - Item na barra de status com cores semafóricas correspondentes ao gate (`APPROVED`, `APPROVED_WITH_RESERVATIONS`, `BLOCKED`, `INCONCLUSIVE`, `REJECTED`).
  - Modo offline automático com fallback para o CLI embarcado.
  - Publicados `packages/vscode-extension/PRIVACY.md`, `packages/vscode-extension/CHANGELOG.md` e suíte de testes de integração (`packages/vscode-extension/test/extension.integration.test.ts`).

### Ação Oficial de CI/CD e Conectores (Bloco C)
- **GitHub Action Oficial (`integrations/github-action/action.yml`):** Suporte aos inputs `gate`, `profile`, `fail-on` e outputs `decision`, `exit-code`, `report-path`, PR decoration automática e integração com `github/codeql-action/upload-sarif`.
- **GitLab CI Component (`templates/winhood.gitlab-ci.yml`) & Exemplos (`examples/.gitlab-ci.yml`):** Bloqueio automático de Merge Requests quando o gate retorna `BLOCKED`.
- **Jenkins Shared Library (`integrations/jenkins/vars/winhoodAnalyze.groovy`, `winhoodGate.groovy`) & `examples/Jenkinsfile`.**
- **Documentação `docs/CI_INTEGRATION.md`:** Especificação canônica de exit codes (`0=APPROVED`, `1=APPROVED_WITH_RESERVATIONS`, `2=BLOCKED`, `3=INCONCLUSIVE`, `4=EXECUTION_ERROR`) e validação de webhooks assinados (`HMAC-SHA256`) em Node.js, Python e Go.

### Transparência Ativa e Cobertura Verificada (Bloco D)
- Publicados `docs/LIMITATIONS.md`, `docs/BIASES.md` e `docs/CONFIDENCE_MODEL.md`.
- Configurados thresholds estritos de cobertura em `package.json` e `scripts/run-coverage-gate.mjs` (`lines >= 80%`, `functions >= 80%`, `branches >= 75%` globalmente e `>= 95%` nos motores críticos `src/scoring`, `src/evidence` e `src/comparability`), gerando artefato HTML (`coverage/index.html`) no CI.

### Relatórios Completos e Assinados nos 4 Formatos (Bloco E)
- Implementado subcomando `winhood report --format=pdf|html|sarif|json` e classe `ReportExporter` (`src/reports/ReportExporter.ts`).
- Geração de HTML5 autocontido (CSS inline, zero requisições externas) e PDF 1.4 binário assinado (`Report-SHA256` + `Report-HMAC-SHA256`) com rodapé completo de proveniência (`engineVersion`, `ruleCatalogVersion`, `ruleCatalogSha256`, `codeHashSha256`, `artifactHashes`, `appliedGateVersion`).
- Publicados exemplos de referência em `examples/reports/` (`sample-report.sarif`, `sample-report.json`, `sample-report.html`, `sample-report.pdf`).
