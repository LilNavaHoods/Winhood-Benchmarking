# Metodologia do Modo MQR — Modern Quality Regime (`MQR_METHODOLOGY.md`)

O **Modo MQR (Modern Quality Regime)** e o **Perfil de Qualidade Estrita** constituem a metodologia oficial do **WinHood Benchmarking** para avaliação multidimensional de qualidade, segurança e confiabilidade de software.

---

## 1. Princípios do Modo MQR (Modern Quality Regime)

Diferentemente de modelos legados que atribuem apenas um rótulo único a cada regra, o **Modo MQR** do WinHood avalia o impacto real de cada achado sobre três dimensões de qualidade de software:

1. **Segurança (`SECURITY`):** Resistência a exploração, injeção, vazamento de credenciais, SSRF, desserialização insegura e falhas de controle de acesso (mapeadas para `CWE` e `OWASP Top 10`).
2. **Confiabilidade (`RELIABILITY`):** Estabilidade em tempo de execução, tratamento de exceções, prevenção de condições de corrida e ausência de falhas lógicas determinísticas.
3. **Manutenibilidade (`MAINTAINABILITY`):** Complexidade ciclomática e cognitiva, modularidade arquitetural, clareza de código e controle de dívida técnica.

---

## 2. Separação Estrita de Escopos e Métricas

1. **Código Global (`Overall Code`) vs. Código Novo (`New Code`):**
   - O Modo MQR avalia tanto o estado acumulado do repositório quanto o delta introduzido na alteração atual, aplicando o princípio de *Clean as You Code* com tolerância de linhas modificadas (*Fudge Factor* `< 20` linhas para cobertura e duplicação em micro-commits).
2. **Separação de Coberturas:**
   - **Cobertura de Ingestão e Parsing:** Percentual de arquivos elegíveis do projeto que foram lidos e convertidos em AST com sucesso pelo WinHood.
   - **Cobertura de Testes (Linhas e Branches):** Percentual medido exclusivamente a partir de relatórios reais de execução de testes (`LCOV` / `Cobertura XML`). A ausência de relatório é registrada como `NOT_MEASURED`, nunca como `0%` ou aprovação implícita.
3. **Independência entre Nota Técnica, Confiança e Gate:**
   - A pontuação técnica (`0.00` a `5.00`), a **Confiança da Evidência** (`HIGH`, `MEDIUM`, `LOW`), a decisão do **Quality Gate** e o resultado do **Motor de Veracidade** são calculados e reportados de forma independente.
