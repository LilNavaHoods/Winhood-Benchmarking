# Relatório de Consistência e Unificação de Quality Gates (`QUALITY_GATE_CONSISTENCY_REPORT.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + unificação Fase 3 (`P0`)
- **Ambiente:** Linux x64, `Node.js v22.23.2`
- **Arquivos principais:** `src/gate/QualityGateEngine.ts`, `src/engine/scoringEngine.ts`, `src/gate/gateAndCompliance.test.ts`
- **Comando executado:** `./node_modules/.bin/tsx --test src/gate/gateAndCompliance.test.ts` (`18/18 PASS`)
- **Estado de validação:** `VALIDATED`

---

## 1. Problema Remediado: Divergência de Contratos e Supressão por `fudgeFactorApplied` (`< 20` linhas)

Na revisão arquitetural (Fase 3):
1. `scoringEngine.ts` possuía uma heurística legada (`fudgeFactorApplied`) inspirada no comportamento de changesets curtos (`< 20` linhas) do SonarQube, capaz de atenuar falhas de Quality Gate em projetos pequenos.
2. **Correção Aplicada:**
   - Em `src/engine/scoringEngine.ts`, a supressão de falhas para `< 20` linhas foi **integralmente removida** (`const fudgeFactorApplied = false;`) e a decisão do Quality Gate do `ScoreCard` passou a delegar diretamente ao avaliador canônico do `QualityGateEngine`.
   - Um único achado `BLOCKER`, `CRITICAL`, `HIGH` (conforme limiar do gate) ou `secrets_exposed > 0` reprova o gate mesmo que o software analisado possua apenas **1 linha de código**.
   - Apenas o adaptador de leitura externa (`src/integrations/mqr-bridge/SonarQualityGateMapper.ts`) preserva o campo informativo `fudgeFactorStatus` para reportar transparentemente quando uma instância remota do SonarQube ignorou condições em PRs curtos.

---

## 2. Matriz dos 9 Cenários Obrigatórios Validados (`src/gate/gateAndCompliance.test.ts`)

| # | Cenário Testado | Entrada | Resultado em `QualityGateEngine.evaluate()` | Resultado em `scoringEngine.ts` (`ScoreCard`) | Consistência |
|---|---|---|---|---|---|
| **1** | **Changeset `< 20` linhas (`8 LOC`) com 1 achado `CRITICAL`** | `critical_findings = 1`, `linesOfCode = 8` | `BLOCKED` (`fudgeFactorApplied = false`) | `FAILED` / `BLOCKED` (`fudgeFactorApplied = false`, teto `2.20`) | `100% Alinhado` |
| **2** | **Changeset `< 20` linhas (`5 LOC`) com 1 achado `HIGH`** | `high_findings = 1` (gate estrito `high_findings EQ 0`), `linesOfCode = 5` | `BLOCKED` / `APPROVED_WITH_RESERVATIONS` conforme severidade da condição | Sem atenuação por tamanho (`fudgeFactorApplied = false`) | `100% Alinhado` |
| **3** | **Changeset `< 20` linhas (`4 LOC`) com 1 segredo exposto (`secrets_exposed = 1`)** | `secrets_exposed = 1`, `linesOfCode = 4` | `BLOCKED` | `FAILED` / `BLOCKED` (Kill-Switch `2.20` acionado) | `100% Alinhado` |
| **4** | **Condição `REQUIRED` com métrica `NOT_MEASURED` (`null`)** | `scope_coverage_percent = null`, `requirementTier = 'REQUIRED'` | `INCONCLUSIVE` (`conditionsInconclusive = 1`) | `INCONCLUSIVE` | `100% Alinhado` |
| **5** | **Condição `OPTIONAL` com métrica `NOT_MEASURED` (`null`)** | Métrica opcional `null`, demais `REQUIRED` aprovadas | `APPROVED_WITH_RESERVATIONS` (ressalva explícita) | `WARN` / `APPROVED_WITH_RESERVATIONS` | `100% Alinhado` |
| **6** | **Condição `INFORMATIVE` com métrica `NOT_MEASURED` ou acima do limiar** | Condição `INFORMATIVE` não atendida, `REQUIRED` aprovadas | `APPROVED` (registrada sem bloquear nem rebaixar) | `PASSED` / `APPROVED` | `100% Alinhado` |
| **7** | **Evidência criptográfica inválida ou adulterada (`evidenceVerified = false`)** | `requireVerifiedEvidence = true`, `evidenceVerified = false` | `INCONCLUSIVE` (nunca `APPROVED`) | `enforceVerifiedQualityGateOnRun` -> `INCONCLUSIVE`, `winner = null` | `100% Alinhado` |
| **8** | **Baixa cobertura de escopo (`scope_coverage_percent = 35% < 50%`)** | `scope_coverage_percent = 35` | `APPROVED_WITH_RESERVATIONS` / `BLOCKED` conforme regra | Ressalva de escopo registrada | `100% Alinhado` |
| **9** | **Equivalência direta entre `evaluate()`, `evaluateFromRun()` e `calculateDeterministicScoreCard()`** | Mesmo conjunto de achados e cobertura submetido às 3 entradas | Mesma decisão canônica e contagens de condições | Mesma decisão refletida no `ScoreCard` | `100% Alinhado` |
