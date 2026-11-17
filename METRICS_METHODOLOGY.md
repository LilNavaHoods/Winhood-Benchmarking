# Metodologia de Métricas, Scoring, Comparabilidade e Quality Gates (`METRICS_METHODOLOGY.md`)

**Versão Metodológica:** `WinHood-Methodology-v4.4.0`

---

## 1. Princípio de Proveniência e Não-Fabricação

1. **Zero Fabricação de Métricas:** Nenhuma dimensão do WinHood recebe nota numérica quando não há evidência verificável. Dimensões sem medição permanecem com `score: null` e `assessmentStatus: 'NOT_ASSESSED'` ou `'INCONCLUSIVE'`.
2. **Separação dos 4 Indicadores Executivos (`separatedIndicators`):**
   - `technicalScore` (0.00 a 5.00, ou `null` quando não avaliado);
   - `scopeCoveragePercent` (0% a 100% de cobertura analítica sobre arquivos elegíveis);
   - `evidenceConfidence` (`HIGH` | `MEDIUM` | `LOW`);
   - `qualityGateDecision` (`APPROVED` | `APPROVED_WITH_RESERVATIONS` | `REJECTED` | `INCONCLUSIVE`).

---

## 2. Profundidade Analítica por Linguagem (`analyticalDepth`)

Cada achado e cada arquivo analisado por `ParserRegistry` declara explicitamente sua profundidade analítica:

| Nível (`ParserAnalyticalDepth`) | Linguagens | Capacidades Reais | Limitações Declaradas |
|---|---|---|---|
| `FULL_AST` | TypeScript, JavaScript, TSX, JSX | AST completa via TypeScript Compiler API, resolução de escopo léxico, CFG e Taint intraprocedural completo. | Fluxos interprocedurais dinâmicos via reflexão/eval são sinalizados como aviso. |
| `STRUCTURAL_AST` | Python, Java, Go, Rust, C#, SQL | Extração estrutural de funções, classes, blocos de controle, chamadas de API e propagação local de taint com sanitizadores contextuais. | Não realiza resolução de tipos entre múltiplos pacotes externos compilados. |
| `PARTIAL_RECOVERY` | Qualquer linguagem com erro sintático parcial | Recuperação tolerante a falhas sobre blocos íntegros do arquivo. | Rebaixa automaticamente achados de confiança `HIGH` para `MEDIUM` e reduz a cobertura analítica efetiva. |
| `UNSUPPORTED` | Binários ou extensões fora do catálogo | Contabilizado em `unsupportedFilesCount`. | Não entra como arquivo analisado. |

---

## 3. Comparabilidade A/B Bimodal (`src/comparability/index.ts`)

O motor de comparabilidade suporta duas modalidades explícitas:

1. **Modalidade 1 — Intraclasse (`SAME_ENGINE`):**
   - Compara dois projetos ou duas versões analisadas pela mesma versão do motor (`engineVersion`) e mesmo catálogo de regras (`ruleCatalogSha256`), mesma categoria funcional e diferença de cobertura de escopo $\le 15\%$.
   - Classificação quando todos os requisitos são cumpridos: `STRICTLY_COMPARABLE`.
2. **Modalidade 2 — Interferramentas (`CROSS_TOOL`):**
   - Permite comparar resultados do motor nativo WinHood com ferramentas externas (ex.: `MqrBridge`, Semgrep/OpenGrep) sobre o **mesmo commit/escopo** utilizando taxonomia normalizada CWE/severidade.
   - Classificação máxima permitida: `QUALIFIED_COMPARISON` (com ressalvas explícitas listando a divergência de motores/catálogos).
3. **Bloqueio de Vencedor (`NOT_COMPARABLE`):**
   - Quando categorias funcionais são incompatíveis, cobertura é insuficiente ($< 50\%$) ou evidências são `LOW`, o par recebe `NOT_COMPARABLE` e `winnerSoftwareId` é obrigatoriamente `null`.

---

## 4. Quality Gates com Três Níveis de Condição (`requirementTier`)

Em `src/gate/QualityGateEngine.ts`, cada condição de um Quality Gate declara seu `requirementTier`:

- **`REQUIRED` (Obrigatória):** Se a métrica for `NOT_MEASURED` (`null`), a condição é marcada como `INCONCLUSIVE` e a decisão global do Gate torna-se `INCONCLUSIVE` (nunca `APPROVED`). Se violar o limiar com severidade `BLOCKER`/`CRITICAL`, a decisão é `REJECTED`.
- **`OPTIONAL` (Opcional):** Se a métrica for `NOT_MEASURED` (`null`), não reprova nem invalida o Gate; registra uma ressalva auditável e degrada `APPROVED` para `APPROVED_WITH_RESERVATIONS`.
- **`INFORMATIVE` (Informativa):** Registrada no laudo como observação técnica para acompanhamento contínuo sem bloquear a aprovação.
