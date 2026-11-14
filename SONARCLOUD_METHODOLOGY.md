# Metodologia Oficial SonarQube Cloud & Governança Analítica no WinHood

## 1. Visão Geral
O WinHood implementa integração direta e auditável com a **Web API oficial do SonarQube Cloud (`https://sonarcloud.io`)** e do **SonarQube Server / Community Build**, preservando a fidelidade metodológica de cada indicador sem inventar valores, sem assumir perfis padrão não verificados e sem confundir métricas oficiais do SonarCloud com pontuações calculadas pelo motor nativo do WinHood.

## 2. Regra de Veracidade (Proibição de Zero Defaulting)
1. **Nenhuma métrica ausente é convertida em `0`, `100` ou Rating `A`**:
   - `SonarMetricsMapper.ts` utiliza `parseStrictInt`, `parseStrictFloat` e `mapNumericToRating`.
   - Quando a API do SonarCloud não retorna uma métrica (por exemplo, `coverage` quando nenhum relatório LCOV/JaCoCo/Cobertura foi enviado ao scanner), o valor permanece `null` e `measurementState: 'NOT_MEASURED'`.
2. **Falhas de API nunca viram "Zero Issues"**:
   - Quando `/api/issues/search` ou `/api/hotspots/search` falha (ex.: HTTP 500, timeout ou erro de rede), `SonarQubeApiClient` registra `pagination.state = 'FAILED'` (ou `'PARTIAL'` se páginas anteriores já haviam sido coletadas) e preserva `errorMessage`.

## 3. Multi-Quality Rule (MQR) Mode vs Standard Experience
O módulo `SonarMetricsMapper` detecta e preserva simultaneamente:
- **Standard Experience**: `bugs`, `vulnerabilities`, `code_smells`, `security_hotspots`, `reliability_rating`, `security_rating`, `sqale_rating`, `security_review_rating`, `sqale_index`, `sqale_debt_ratio`.
- **Multi-Quality Rule (MQR) Mode**:
  - `software_quality_security_issues`, `software_quality_reliability_issues`, `software_quality_maintainability_issues`
  - `software_quality_security_rating`, `software_quality_reliability_rating`, `software_quality_maintainability_rating`
  - `cleanCodeAttribute`, `cleanCodeAttributeCategory` (`CONSISTENT`, `INTENTIONAL`, `ADAPTABLE`, `RESPONSIBLE`) e `impacts[]` (`softwareQuality` + `severity: BLOCKER | HIGH | MEDIUM | LOW | INFO`).

## 4. Separação entre Overall Code e New Code (Clean as You Code)
- **Overall Code**: reflete o estoque total do repositório (`bugs`, `vulnerabilities`, `code_smells`, `coverage`, `duplicated_lines_density`).
- **New Code**: reflete exclusivamente o período de código novo (`new_bugs`, `new_vulnerabilities`, `new_code_smells`, `new_security_hotspots`, `new_coverage`, `new_branch_coverage`, `new_duplicated_lines_density`, `new_technical_debt`, `new_reliability_rating`, `new_security_rating`, `new_maintainability_rating`, `new_security_review_rating`).

## 5. Quality Gates, Condições Individuais e Fudge Factor
`SonarQualityGateMapper.ts` consulta `/api/qualitygates/project_status` e `/api/qualitygates/get_by_project`:
- Preserva os estados `OK`, `ERROR`, `WARN`, `NONE`, `NOT_COMPUTED` e `API_ERROR`.
- Classifica cada condição individual por escopo (`NEW_CODE` vs `OVERALL_CODE`), valor medido (`actualValue`), limite (`Comparator` + `errorThreshold`), estado e justificativa técnica (`reasonText`).
- Identifica quando o **Fudge Factor** de changesets curtos do SonarCloud é aplicado (`fudgeFactorStatus: 'APPLIED_SHORT_CHANGESET'` quando `new_coverage` ou `new_duplicated_lines_density` permanece `OK` em changeset inferior a 20 linhas elegíveis).

## 6. Security Hotspots Breakdown
`SonarResultParser.computeHotspotsBreakdown` separa rigorosamente:
- `totalIdentified`: total de Security Hotspots retornados.
- `unreviewedCount`: hotspots com `status === 'TO_REVIEW'`.
- `reviewedSafeCount`: hotspots revisados com `resolution === 'SAFE'`.
- `reviewedFixedCount`: hotspots revisados com `resolution === 'FIXED'`.
- `acceptedRiskCount`: hotspots revisados com `resolution === 'ACKNOWLEDGED'`.
- `reviewedVulnerableCount`: hotspots convertidos/confirmados como vulneráveis.
- `reviewPercent`: calculado apenas quando `totalIdentified > 0` (`null` quando `0` ou `NOT_MEASURED`).
