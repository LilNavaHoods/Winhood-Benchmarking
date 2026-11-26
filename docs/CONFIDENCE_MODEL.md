# Modelo Matemático de Confiança da Evidência (`docs/CONFIDENCE_MODEL.md`)

No **WinHood Benchmarking**, a **Confiança da Evidência (`Evidence Confidence`)** é um indicador de primeira classe, estritamente separado da **Nota Técnica (`0.00–5.00`)** e da decisão do **Quality Gate**. Ele responde à pergunta:

> *"Quão completa, verificável e tecnicamente defensável é a base de provas sobre a qual esta avaliação foi calculada?"*

---

## 1. Variáveis de Entrada do Modelo

O cálculo determinístico da Confiança da Evidência considera cinco fatores mensuráveis da execução:

1. **Cobertura de Ingestão e Parsing ($C_{\text{scope}} \in [0, 1]$):**
   $$C_{\text{scope}} = \frac{\text{Arquivos Elegíveis Processados com Sucesso}}{\text{Total de Arquivos Elegíveis no Escopo}}$$
2. **Integridade Criptográfica da Trilha ($I_{\text{crypto}} \in \{0, 1\}$):**
   - $I_{\text{crypto}} = 1$ se e somente se a cadeia `SHA-256` append-only não apresentar elos corrompidos e a assinatura do manifesto (`HMAC-SHA256` / `Ed25519`), incluindo `provenanceMetadata` (`winhoodVersion`, hashes de entrada/saída, versões dos analisadores e `scaFreshnessStatus`), for validada com sucesso (`verificationState === 'VERIFIED'`). Caso contrário, $I_{\text{crypto}} = 0$.
   - *Escopo da garantia:* a assinatura provê evidência de adulteração (*tamper-evidence*) pós-emissão, não prova de ausência total de vulnerabilidades.
3. **Profundidade Analítica ($D_{\text{ast}} \in [0, 1]$):**
   - Proporção ponderada de arquivos analisados com `FULL_AST` + call-graph taint (`1.0`, TS/JS) versus `STRUCTURAL_AST` (`0.75`, Python/Java/Go/C#/Rust/SQL) versus inventário superficial (`0.30`). Caminhos incompletos de taint (`DYNAMIC_CALL_DISPATCH`, `MAX_DEPTH_REACHED`, `CYCLE_DETECTED`, `RESOURCE_BUDGET_EXCEEDED`) e cadeias multi-hop profundas (`> 4` saltos) reduzem a confiança do achado individual para `MEDIUM` ou `INCONCLUSIVE`.
4. **Completude das Dimensões Elegíveis e Frescor SCA ($M_{\text{dim}} \in [0, 1]$):**
   - Razão entre categorias com estado `MEASURED` / `STATIC_DERIVED` e o total de categorias habilitadas no perfil de avaliação.
   - Dados SCA em `OFFLINE_LIMITED_BASELINE` ou `STALE_DATA` são sinalizados explicitamente nas limitações de proveniência e impedem reivindicação de cobertura SCA abrangente.
5. **Determinismo e Estado de Execução de Ferramentas ($R_{\text{det}} \in [0, 1]$):**
   - Penaliza falhas parciais (`PARTIAL`, `EXECUTION_FAILED`), timeouts (`TIMED_OUT`) ou ferramentas externas bloqueadas (`BLOCKED` / `NOT_INSTALLED`) quando exigidas pelo perfil.

---

## 2. Fórmula do Índice Composto de Confiança ($E_{\text{score}}$)

Quando $I_{\text{crypto}} = 1$, o índice contínuo $E_{\text{score}} \in [0, 100]$ é calculado por:

$$E_{\text{score}} = \text{round}\Big(100 \times \big(0.40 \cdot C_{\text{scope}} + 0.25 \cdot D_{\text{ast}} + 0.20 \cdot M_{\text{dim}} + 0.15 \cdot R_{\text{det}}\big)\Big)$$

Se $I_{\text{crypto}} = 0$ (falha de verificação criptográfica, adulteração de `provenanceMetadata` ou manifesto ausente em execução que exige assinatura), a confiança é imediatamente rebaixada para `LOW` ($E_{\text{score}} \le 30$).

---

## 3. Classificação Qualitativa e Decisões Estritas do Quality Gate

O `QualityGateEngine` distingue rigorosamente entre falha de critério, bloqueio operacional, inconclusividade por ausência de medição (`NOT_MEASURED`) e aprovação:

| Nível de Confiança / Estado | Critério Determinístico | Decisão de Gate & Código CLI |
| :--- | :--- | :--- |
| **`HIGH`** | $E_{\text{score}} \ge 80$, $C_{\text{scope}} \ge 0.85$ e $I_{\text{crypto}} = 1$ | Permite **`APPROVED`** (`exit 0`) quando todas as condições obrigatórias passam; **`BLOCKED`** / **`REJECTED`** (`exit 1`) se qualquer vulnerabilidade crítica/blocker violar limiar. |
| **`MEDIUM`** | $50 \le E_{\text{score}} < 80$ ou $0.50 \le C_{\text{scope}} < 0.85$ (com $I_{\text{crypto}} = 1$) | **`APPROVED_WITH_RESERVATIONS`** (`exit 0` com ressalvas explícitas) ou **`INCONCLUSIVE`** (`exit 2`) em perfis estritos quando métricas obrigatórias estão `NOT_MEASURED`. |
| **`LOW` / `NOT_MEASURED`** | $E_{\text{score}} < 50$, $C_{\text{scope}} < 0.50$, $I_{\text{crypto}} = 0$, ou métrica obrigatória ausente (`null` / `NOT_MEASURED`) | Retorna obrigatoriamente **`INCONCLUSIVE`** (`exit 2`) — ou **`BLOCKED`** (`exit 1`) se houver vulnerabilidade crítica já comprovada — impedindo aprovações silenciosas sem dados. |

---

## 4. Como Interpretar nos Relatórios e na UI

- **Nota Alta (`4.80 / 5.00`) + Confiança `LOW` ou Gate `INCONCLUSIVE`:** Poucos arquivos foram auditados ou métricas obrigatórias ficaram `NOT_MEASURED`. **Não deve ser aprovado para produção.**
- **Nota Baixa (`1.90 / 5.00`) + Confiança `HIGH` + Gate `BLOCKED`:** Vulnerabilidades reais foram comprovadas em análise abrangente e assinada. **Requer bloqueio e remediação.**
- **Nota Alta (`4.65 / 5.00`) + Confiança `HIGH` + Gate `APPROVED`:** Evidência técnica verificável e assinada de conformidade com o perfil aplicado, respeitando as fronteiras declaradas em `docs/LIMITATIONS.md`.
