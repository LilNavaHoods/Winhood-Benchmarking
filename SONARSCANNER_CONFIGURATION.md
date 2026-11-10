# SONARSCANNER_CONFIGURATION.md — Gerenciamento e Configuração do SonarScanner

## 1. Documentação Oficial de Referência
- https://docs.sonarsource.com/sonarqube-community-build/analyzing-source-code/scanners/sonarscanner

## 2. Seleção Automática de Scanner (`SonarScannerManager`)
Localizado em `src/integrations/sonarqube/SonarScannerManager.ts`, o componente inspeciona a árvore de arquivos e linguagens do Software A e do Software B e seleciona automaticamente o scanner específico prioritário:
1. **Maven (`SONAR_SCANNER_MAVEN` v5.0.0.4389):** Projetos com `pom.xml`.
2. **Gradle (`SONAR_SCANNER_GRADLE` v6.0.1.5171):** Projetos com `build.gradle` ou `build.gradle.kts`.
3. **.NET (`SONAR_SCANNER_DOTNET` v9.0.2):** Projetos C# / F# com `.csproj` ou `.sln`.
4. **NPM (`SONAR_SCANNER_NPM` `@sonar/scan` v4.2.5):** Projetos TypeScript / JavaScript com `package.json`.
5. **Python (`SONAR_SCANNER_PYTHON` `pysonar` v1.1.0):** Projetos com `pyproject.toml` ou `requirements.txt`.
6. **SonarScanner CLI (`SONAR_SCANNER_CLI` v8.4.0.16527):** Projetos poliglotas, C/C++, Go, SQL ou sem scanner específico.
   - Checksum SHA-256 Oficial Linux x64: `2a28f118e2e9375dfd36eb27b803e1d37f93daba4db068aca6eef9853041bb24`
   - Checksum SHA-256 Oficial Windows x64: `9998fca7f8897975f8fad850aa92e5a236441ace6c6126a15da34f5a049795ce`

## 3. Propriedades Geradas e Reprodutibilidade
Para cada execução, o `SonarScannerManager` gera e registra:
- `sonar.projectKey` (exclusivo para Software A e Software B)
- `sonar.projectName`
- `sonar.projectBaseDir`
- `sonar.sources`
- `sonar.tests`
- `sonar.exclusions` (nenhuma exclusão é aplicada silenciosamente sem justificativa auditável registrada)
- `sonar.host.url`
- `sonar.sarifReportPaths` (quando há importação de relatórios externos SARIF 2.1.0)

## 4. Segurança dos Tokens (`SONAR_TOKEN`)
- O token **nunca** é gravado em `sonar-project.properties`, **nunca** é passado na linha de comando (`-Dsonar.token=...` é proibido para evitar exposição em `ps aux`), **nunca** é enviado em parâmetros de URL e **nunca** é retornado ao frontend.
- O scanner recebe a credencial exclusivamente via variável de ambiente `SONAR_TOKEN` no worker de backend, e o armazenamento em disco utiliza criptografia `AES-256-GCM`.
