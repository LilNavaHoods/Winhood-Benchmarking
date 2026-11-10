# SONARQUBE_API.md — Integração com a Web API do SonarQube

## 1. Documentação Oficial
- https://docs.sonarsource.com/sonarqube-community-build/extension-guide/web-api

## 2. Endpoints Utilizados pelo `SonarQubeApiClient`
Implementado em `src/integrations/sonarqube/SonarQubeApiClient.ts`, o cliente utiliza autenticação HTTP `Authorization: Bearer <SONAR_TOKEN>` sem qualquer scraping de HTML:
- `GET /api/system/status` — Verifica disponibilidade operacional (`UP`, `STARTING`, etc.) e versão instalada.
- `GET /api/authentication/validate` — Valida o token Bearer e recupera metadados de expiração.
- `POST /api/projects/create` — Provisiona os projetos exclusivos para Software A e Software B.
- `GET /api/ce/task?id=<ceTaskId>` — Acompanha o processamento assíncrono no Compute Engine com *exponential backoff* (`SonarAnalysisRunner.waitForComputeEngineTask()`), aguardando o estado `SUCCESS` antes de consultar as métricas finais.
- `GET /api/measures/component` — Recupera `bugs`, `vulnerabilities`, `security_hotspots`, `security_hotspots_reviewed`, `code_smells`, `complexity`, `cognitive_complexity`, `duplicated_lines_density`, `ncloc`, `sqale_index`, `sqale_rating`, `reliability_rating`, `security_rating`, `coverage`, `lines_to_cover`, `uncovered_lines`, `conditions_to_cover`, `new_coverage`.
- `GET /api/issues/search` — Recupera issues estáticas nativas e issues externas importadas via SARIF (`externalRuleEngine`).
- `GET /api/hotspots/search` — Recupera Security Hotspots e seu estado de revisão (`TO_REVIEW`, `REVIEWED`).
- `GET /api/qualitygates/project_status` — Recupera o resultado do Quality Gate (`OK`, `ERROR`, `WARN`) e o detalhamento de cada condição atendida ou reprovada.
- `GET /api/qualityprofiles/search` — Verifica a consistência dos perfis de qualidade aplicados entre Software A e Software B.

## 3. Estruturas de Persistência (13 Coleções Auditáveis)
Os dados normalizados e os hashes SHA-256 das respostas originais são persistidos em:
`sonar_instances`, `sonar_installations`, `sonar_versions`, `sonar_scanners`, `sonar_projects`, `sonar_analyses`, `sonar_tasks`, `sonar_issues`, `sonar_measures`, `sonar_quality_gates`, `sonar_quality_profiles`, `sonar_integrations` e `sonar_execution_logs`.
