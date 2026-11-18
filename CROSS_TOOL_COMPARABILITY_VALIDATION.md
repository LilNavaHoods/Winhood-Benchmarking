# Validação de Comparabilidade A/B e Cross-Tool (`CROSS_TOOL_COMPARABILITY_VALIDATION.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + endurecimento de manifesto Fase 6
- **Ambiente:** Linux x64, `Node.js v22.23.2`
- **Arquivos principais:** `src/comparability/index.ts`, `src/intelligence/comparison/BenchmarkMatcher.ts`, `src/gate/gateAndCompliance.test.ts`, `src/components/uiAndE2e.test.ts`
- **Comandos executados:** `./node_modules/.bin/tsx --test src/gate/gateAndCompliance.test.ts` e `npm run test:coverage`
- **Cobertura medida em `src/comparability/index.ts`:** `100.00%` Lines · `100.00%` Functions · `98.08%` Branches (`85 -> 93/95` branches cobertos)
- **Estado de validação:** `VALIDATED`

---

## 1. Estrutura Verificável do `ComparabilityManifest`

Para impedir que comparações A/B (`SAME_ENGINE` ou `CROSS_TOOL`) sejam aprovadas com base apenas em flags booleanas autodeclaradas (`sameCommitVerified: true` ou `normalizedTaxonomyApplied: true`), `validatePairComparability()` exige que tanto o `candidateA` quanto o `candidateB` apresentem um objeto `ComparabilityManifest` íntegro contendo:

| Campo do Manifesto | Regra de Validação em `validateManifestPresenceAndIntegrity()` | Efeito em Caso de Ausência/Divergência |
|---|---|---|
| `projectId` | String não vazia; deve coincidir entre A e B tanto em `SAME_ENGINE` quanto em `CROSS_TOOL`. | `NOT_COMPARABLE` (`INCOMPATIBLE_SCOPE`) |
| `commitSha` | String com $\ge 7$ caracteres; em `CROSS_TOOL` (ou quando `sameCommitVerified: true`) deve ser **idêntico** entre A e B. | `NOT_COMPARABLE` |
| `engineVersion` & `analyticalProfile` | Strings obrigatórias; em `SAME_ENGINE` devem coincidir exatamente. | `NOT_COMPARABLE` em `SAME_ENGINE`; gera qualificação explícita em `CROSS_TOOL` |
| `configHashSha256` | Hash SHA-256 hexadecimal de 64 caracteres (`isValidSha256Hex`). Deve coincidir em `SAME_ENGINE`. | `NOT_COMPARABLE` |
| `weightsHashSha256` | Hash SHA-256 hexadecimal de 64 caracteres. Deve coincidir em `SAME_ENGINE`. | `NOT_COMPARABLE` |
| `eligibleFilesScopeHash` | Hash SHA-256 hexadecimal de 64 caracteres do conjunto de arquivos elegíveis. | Se divergir, rebaixa `STRICTLY_COMPARABLE` para `QUALIFIED_COMPARISON` com ressalva explícita. |
| `taxonomyMappingSha256` | Hash SHA-256 de 64 caracteres da especificação de mapeamento CWE/MQR (`CANONICAL_TAXONOMY_MAPPING_SHA256`). Obrigatório e idêntico em `CROSS_TOOL`. | `NOT_COMPARABLE` |
| `evidenceIntegrityVerified` | Deve ser `true` em ambos os candidatos. | `NOT_COMPARABLE` |

---

## 2. Regras Anti-Bypass Verificadas por Testes Automatizados

1. **Chamada sem `manifest` (`manifest: undefined`):**
   - Rejeitada imediatamente com `comparable: false`, `comparabilityClassification: 'NOT_COMPARABLE'` e motivo explícito: `"Manifesto de Comparabilidade verificável ausente (proibido aceitar comparação sem manifesto)."`.
2. **Bypass com `sameCommitVerified: true` mas `commitSha` divergente ou curto (`< 7` chars):**
   - Rejeitada com `"Flag booleana sameCommitVerified=true rejeitada: commitSha ausente ou divergente no manifesto."`.
3. **Bypass com `normalizedTaxonomyApplied: true` mas `taxonomyMappingSha256` ausente/inválido:**
   - Rejeitada com `"Flag booleana normalizedTaxonomyApplied=true rejeitada: taxonomyMappingSha256 ausente ou inválido no manifesto."` (verificado tanto em `gateAndCompliance.test.ts` quanto no **Fluxo 7** de `src/components/uiAndE2e.test.ts`).
4. **Ferramenta não executada (`toolExecuted: false`):**
   - Rejeitada com `"Execução real de uma ou mais ferramentas ausente (toolExecuted=false)."`.
5. **Confiança da evidência `LOW`:**
   - Retorna `status: 'INCONCLUSIVE'`, `comparable: false`, `comparabilityClassification: 'NOT_COMPARABLE'`.
6. **Bloqueio de Vencedor:**
   - Sempre que `comparabilityClassification === 'NOT_COMPARABLE'`, o orquestrador e o `BenchmarkMatcher` bloqueiam a eleição de vencedor (`winnerSoftwareId = null`).
