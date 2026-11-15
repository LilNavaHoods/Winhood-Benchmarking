# EXTERNAL_TOOLS.md — Governança de Ingestão Externa via Padrões Abertos

## 1. Especificação de Padrões Abertos Suportados
- **OASIS SARIF 2.1.0 (`Static Analysis Results Interchange Format`)**: Esquema canônico para intercâmbio de resultados de análise estática, fluxo de dados (`codeFlows`) e metadados de regras (`CWE`, `OWASP Top 10`, `CVSS`).
- **OWASP CycloneDX 1.5 & Linux Foundation SPDX 2.3**: Formatos abertos para inventário de componentes e dependências de software (SBOM).

## 2. Categorias de Ferramentas que Exportam SARIF (`ExternalReportImportWorker`)
O componente `src/workers/ExternalReportImportWorker.ts` suporta a ingestão de artefatos gerados por quaisquer **ferramentas que exportam SARIF 2.1.0** ou formatos abertos de cobertura:

| Categoria de Emissor | Formato Aberto | Propriedade de Ingestão | Preservação de Proveniência |
| :--- | :--- | :--- | :--- |
| **Analisadores SAST e AST** | SARIF 2.1.0 | `winhood.sarifReportPaths` | `isExternalImportedRule: true` |
| **Analisadores de Fluxo (Taint)** | SARIF 2.1.0 (`codeFlows`) | `winhood.sarifReportPaths` | `isExternalImportedRule: true` |
| **Detectores de Segredos** | SARIF 2.1.0 | `winhood.sarifReportPaths` | `isExternalImportedRule: true` |
| **Analisadores de Containers e IaC** | SARIF 2.1.0 | `winhood.sarifReportPaths` | `isExternalImportedRule: true` |
| **Linters Estruturais Multi-Linguagem** | SARIF 2.1.0 / JSON | `winhood.sarifReportPaths` | `isExternalImportedRule: true` |
| **Executores de Cobertura de Testes** | LCOV / Cobertura XML | `winhood.coverageReportPaths` | `sourceType: EXTERNAL_TEST_REPORT_IMPORTED` |

## 3. Regra de Não-Confusão com Perfis Nativos do WinHood
Achados importados de ferramentas que exportam SARIF possuem ciclo de vida e rastreabilidade estritamente separados das regras nativas do WinHood:
- Nunca são confundidos com métricas calculadas nativamente pelo motor do WinHood (`WINHOOD_NATIVE`);
- Mantêm registrados no banco principal: `externalOriginTool`, `externalOriginVersion`, `originalRuleId`, `severity`, `confidence`, `filePath`, `lineNumber` e `evidenceSha256`;
- São deduplicados deterministicamente por chave canônica (`filePath + lineNumber + cwe + category`) preservando a cadeia de evidências.
