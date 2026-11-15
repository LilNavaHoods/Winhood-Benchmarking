# Modelo Matemático de Confiança da Evidência (`docs/CONFIDENCE_MODEL.md`)

No **WinHood Benchmarking**, a **Confiança da Evidência (`Evidence Confidence`)** é um indicador de primeira classe, estritamente separado da **Nota Técnica (`0.00–5.00`)** e da decisão do **Quality Gate**. Ele responde à pergunta:

> *"Quão completa, verificável e digna de confiança é a base de provas sobre a qual esta avaliação foi calculada?"*

---

## 1. Variáveis de Entrada do Modelo

O cálculo determinístico da Confiança da Evidência considera cinco fatores mensuráveis da execução:

1. **Cobertura de Ingestão e Parsing ($C_{\text{scope}} \in [0, 1]$):**
   $$C_{\text{scope}} = \frac{\text{Arquivos Elegíveis Processados com Sucesso}}{\text{Total de Arquivos Elegíveis no Escopo}}$$
2. **Integridade Criptográfica da Trilha ($I_{\text{crypto}} \in \{0, 1\}$):**
   - $I_{\text{crypto}} = 1$ se e somente se a cadeia `SHA-256` append-only não apresentar elos corrompidos e a assinatura do manifesto (`HMAC-SHA256` / `Ed25519`) for validada com sucesso (`verificationState === 'VERIFIED'`). Caso contrário, $I_{\text{crypto}} = 0$.
3. **Profundidade Analítica ($D_{\text{ast}} \in [0, 1]$):**
   - Proporção ponderada de arquivos analisados com AST + Taint completo ($1.0$) versus análise estrutural ($0.75$) ou apenas inventário superficial ($0.30$).
4. **Completude das Dimensões Elegíveis ($M_{\text{dim}} \in [0, 1]$):**
   - Razão entre categorias com estado `MEASURED` / `STATIC_DERIVED` e o total de categorias habilitadas no perfil de avaliação.
5. **Determinismo de Execução ($R_{\text{det}} \in [0, 1]$):**
   - Penaliza falhas parciais de adaptadores (`PARTIAL`, `API_ERROR`) ou timeouts de execução isolada.

---

## 2. Fórmula do Índice Composto de Confiança ($E_{\text{score}}$)

Quando $I_{\text{crypto}} = 1$, o índice contínuo $E_{\text{score}} \in [0, 100]$ é calculado por:

$$E_{\text{score}} = \text{round}\Big(100 \times \big(0.40 \cdot C_{\text{scope}} + 0.25 \cdot D_{\text{ast}} + 0.20 \cdot M_{\text{dim}} + 0.15 \cdot R_{\text{det}}\big)\Big)$$

Se $I_{\text{crypto}} = 0$ (falha de verificação criptográfica ou manifesto ausente em execução que exige assinatura), a confiança é imediatamente rebaixada para `LOW` ($E_{\text{score}} \le 30$).

---

## 3. Classificação Qualitativa e Impacto no Quality Gate

| Nível de Confiança | Critério Determinístico | Interpretação Executiva e Impacto no Gate |
| :--- | :--- | :--- |
| **`HIGH`** | $E_{\text{score}} \ge 80$, $C_{\text{scope}} \ge 0.85$ e $I_{\text{crypto}} = 1$ | **Alta Confiabilidade:** Cobertura ampla do código-fonte, AST completa e cadeia criptográfica íntegra. Permite aprovação plena (`APPROVED`) no Quality Gate. |
| **`MEDIUM`** | $50 \le E_{\text{score}} < 80$ ou $0.50 \le C_{\text{scope}} < 0.85$ (com $I_{\text{crypto}} = 1$) | **Confiabilidade Moderada:** Parte relevante do escopo foi analisada, mas há dimensões não mensuradas (`NOT_MEASURED`) ou cobertura parcial. Em perfis Zero-Trust, resulta em `APPROVED_WITH_RESERVATIONS` ou `INCONCLUSIVE`. |
| **`LOW`** | $E_{\text{score}} < 50$, $C_{\text{scope}} < 0.50$ ou $I_{\text{crypto}} = 0$ | **Baixa Confiabilidade:** Escopo insuficiente para atestar qualidade com segurança. O Quality Gate retorna obrigatoriamente **`INCONCLUSIVE`** (ou `BLOCKED` se houver vulnerabilidade crítica já detectada), impedindo falsos positivos de aprovação. |

---

## 4. Como Interpretar nos Relatórios e na UI

- **Nota Alta (`4.80 / 5.00`) + Confiança `LOW`:** Significa que nos poucos arquivos analisados não foram encontrados problemas, mas a maior parte do software não pôde ser auditada. **Não deve ser aprovado para produção.**
- **Nota Baixa (`1.90 / 5.00`) + Confiança `HIGH`:** Significa que vulnerabilidades reais e verificadas foram comprovadas em uma análise abrangente e assinada. **Requer bloqueio imediato e remediação.**
- **Nota Alta (`4.65 / 5.00`) + Confiança `HIGH` + Gate `APPROVED`:** Evidência técnica robusta, reproduzível e assinada de conformidade com o perfil de qualidade aplicado.
