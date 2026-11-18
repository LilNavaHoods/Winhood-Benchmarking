# Metodologia de Métricas, Scoring, Comparabilidade e Quality Gates (`METRICS_METHODOLOGY.md`)

- **Versão do WinHood:** `4.4.0` (`WinHood-Methodology-v4.4.0`)
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + alinhamento de contratos Fase 3/4/6/7
- **Ambiente:** Linux x64, `Node.js v22.23.2`
- **Comandos de verificação:** `npm test`, `npm run test:coverage`, `npm run test:golden`
- **Estado de validação:** `VALIDATED`

---

## 1. Princípio de Proveniência e Não-Fabricação (Lei Fundamental)

1. **Zero Fabricação de Métricas:** Nenhuma dimensão do WinHood ou cartão da UI recebe valor numérico quando não há medição real. Categorias e telemetrias ausentes permanecem `null` no modelo de dados e são exibidas na interface como `NOT_MEASURED` / `NÃO MEDIDO` / `N/A`.
2. **Separação dos 3 Indicadores de Cobertura (`computeThreeWaySeparatedCoverage`):**
   - `testCoverage`: Cobertura de linhas, funções, branches e statements medida via `c8` + `v8-to-istanbul` (`all: true`) ou relatórios LCOV/JaCoCo/Cobertura importados.
   - `ingestionCoverage`: Proporção de arquivos elegíveis lidos em relação ao total descoberto.
   - `analysisCoverage`: Proporção de arquivos elegíveis interpretados pelos parsers (`FULL_AST`, `STRUCTURAL_AST`, `PARTIAL_RECOVERY`).

---

## 2. Comparabilidade A/B Baseada em Manifesto Verificável (`src/comparability/index.ts`)

1. **Obrigatoriedade de `ComparabilityManifest`:** Nenhuma comparação `SAME_ENGINE` ou `CROSS_TOOL` é aceita sem `manifest` válido em ambos os candidatos contendo `projectId`, `commitSha` ($\ge 7$ chars), `engineVersion`, `analyticalProfile`, `configHashSha256`, `weightsHashSha256`, `eligibleFilesScopeHash` e `evidenceIntegrityVerified: true`.
2. **Proibição de Flags Booleanas Soltas:** Passar `sameCommitVerified: true` ou `normalizedTaxonomyApplied: true` sem que os respectivos campos `commitSha` idênticos e `taxonomyMappingSha256` (hash SHA-256 de 64 hex chars) constem nos manifestos resulta em rejeição imediata (`NOT_COMPARABLE`).
3. **Classificações:**
   - `STRICTLY_COMPARABLE`: `SAME_ENGINE`, mesmos hashes de catálogo/pesos/configuração/commit/escopo, árvore limpa, mesmo SO/runtime, $\Delta\text{cobertura} \le 10\%$ e confiança `HIGH`.
   - `QUALIFIED_COMPARISON`: Comparação válida em `CROSS_TOOL` (mesmo `projectId`, mesmo `commitSha`, mesmo `taxonomyMappingSha256`) ou `SAME_ENGINE` com ressalvas documentadas ($10\% < \Delta\text{cobertura} \le 30\%$, confiança `MEDIUM`, runtime distinto).
   - `NOT_COMPARABLE`: Bloqueia proclamação de vencedor (`winnerSoftwareId = null`).

---

## 3. Contrato Unificado de Quality Gate Sem Supressão por Tamanho (`src/gate/QualityGateEngine.ts`)

1. **Remoção de `fudgeFactorApplied` no Motor WinHood:** O WinHood **nunca** suprime achados `BLOCKER`, `CRITICAL`, `HIGH` ou `secrets_exposed` porque o changeset possui menos de 20 linhas (`fudgeFactorApplied` é permanentemente `false` no `scoringEngine.ts` e `QualityGateEngine.ts`; apenas o conector externo `SonarQualityGateMapper.ts` relata quando um servidor Sonar remoto aplicou essa heurística).
2. **Três Níveis de Condição (`requirementTier`):**
   - `REQUIRED`: Valor `null` (`NOT_MEASURED`) torna a decisão `INCONCLUSIVE`; violação com `severityOnFail: 'BLOCKER'` resulta em `BLOCKED` / `REJECTED`; violação com `RESERVATION` resulta em `APPROVED_WITH_RESERVATIONS`.
   - `OPTIONAL`: Valor `null` ou falha de limiar registra ressalva e resulta em `APPROVED_WITH_RESERVATIONS`.
   - `INFORMATIVE`: Registrada apenas para observabilidade, sem alterar `APPROVED`.
