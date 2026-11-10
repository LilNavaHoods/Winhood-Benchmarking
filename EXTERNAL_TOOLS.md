# EXTERNAL_TOOLS.md — Governança de Ferramentas Externas e Importação SARIF

## 1. Documentação Oficial de Importação Externa do SonarQube
- https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/importing-external-issues/
- https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/importing-external-issues/importing-issues-from-sarif-reports

## 2. Ferramentas Externas Compatíveis (`ExternalReportImportWorker`)
O componente `src/workers/ExternalReportImportWorker.ts` suporta a importação de relatórios SARIF 2.1.0 e relatórios nativos para o SonarQube e para o Benchmark Analyzer:

| Ferramenta | Formato | Propriedade SonarScanner | Preservação de Origem |
| :--- | :--- | :--- | :--- |
| **Semgrep / Opengrep** | SARIF 2.1.0 | `sonar.sarifReportPaths` | `isExternalImportedRule: true` |
| **GitHub CodeQL** | SARIF 2.1.0 | `sonar.sarifReportPaths` | `isExternalImportedRule: true` |
| **Gitleaks** | SARIF 2.1.0 | `sonar.sarifReportPaths` | `isExternalImportedRule: true` |
| **Aqua Trivy** | SARIF 2.1.0 | `sonar.sarifReportPaths` | `isExternalImportedRule: true` |
| **PyCQA Bandit** | SARIF / JSON | `sonar.python.bandit.reportPaths` | `isExternalImportedRule: true` |
| **Astral Ruff** | SARIF / JSON | `sonar.python.ruff.reportPaths` | `isExternalImportedRule: true` |
| **ESLint** | SARIF / JSON | `sonar.eslint.reportPaths` | `isExternalImportedRule: true` |
| **SpotBugs** | XML Nativo | `sonar.java.spotbugs.reportPaths` | `isExternalImportedRule: true` |
| **PMD** | SARIF / XML | `sonar.java.pmd.reportPaths` | `isExternalImportedRule: true` |
| **Checkstyle** | SARIF / XML | `sonar.java.checkstyle.reportPaths` | `isExternalImportedRule: true` |

## 3. Regra de Não-Confusão com Quality Profiles Nativos
Achados importados de ferramentas externas possuem ciclo de vida distinto das regras nativas do SonarQube:
- Não são gerenciados pelos Quality Profiles nativos do SonarQube;
- Mantêm registrados no banco principal: `externalOriginTool`, `externalOriginVersion`, `originalRuleId`, `severity`, `confidence`, `filePath`, `lineNumber` e `evidenceSha256`;
- São deduplicados determinísticamente para evitar inflar a contagem de vulnerabilidades ou code smells.
