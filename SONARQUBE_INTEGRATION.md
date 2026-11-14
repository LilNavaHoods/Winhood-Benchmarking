# Integração SonarQube Cloud, SonarQube Server & Community Build

## 1. Arquitetura de Integração Oficial via Web API
A camada de integração do WinHood (`src/integrations/sonarqube/`) utiliza exclusivamente os endpoints REST oficiais do SonarQube Cloud e SonarQube Server:
- `/api/system/status` — Verificação de disponibilidade e versão do servidor.
- `/api/authentication/validate` e `/api/user_tokens/search` — Validação do token Bearer e consulta de expiração.
- `/api/qualityprofiles/search` — Descoberta dos Quality Profiles reais vinculados ao projeto (`VERIFIED_SONAR_WAY`, `VERIFIED_CUSTOM` ou `NOT_VERIFIED`).
- `/api/qualitygates/project_status` e `/api/qualitygates/get_by_project` — Status do Quality Gate, condições individuais e Fudge Factor.
- `/api/measures/component` — Coleta simultânea de 39 métricas cobrindo Standard Experience, MQR, New Code e Cobertura separada.
- `/api/issues/search` — Paginação completa (`p`, `ps`, `total`, limite de 10.000 registros) com `additionalFields=_all` e `facets`.
- `/api/hotspots/search` — Paginação completa de Security Hotspots e cálculo de revisão (`computeHotspotsBreakdown`).
- `/api/ce/task` — Polling assíncrono do Compute Engine após submissão via SonarScanner.

## 2. Preservação de `sonar-project.properties`
`SonarScannerExecutor.ts` **nunca sobrescreve** o arquivo `sonar-project.properties` existente no repositório do usuário. Em vez disso:
- Gera um arquivo temporário `.winhood-sonar-<timestamp>-<uuid>.properties`.
- Passa `-Dproject.settings=<caminho_temporario>` para o processo do scanner.
- Remove o arquivo temporário no bloco `finally`.
