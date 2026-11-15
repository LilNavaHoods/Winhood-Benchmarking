# Vieses Conhecidos do Motor de Pontuação e Mitigações (`docs/BIASES.md`)

Qualquer modelo matemático de pontuação de software está sujeito a vieses estruturais caso trate projetos heterogêneos de forma ingênua. Este documento descreve os vieses conhecidos identificados na engenharia do **WinHood Benchmarking** e os mecanismos matemáticos implementados em `src/engine/scoringEngine.ts` e `src/intelligence/comparison/BenchmarkMatcher.ts` para mitigá-los.

---

## 1. Viés de Escala e Volume de Código (`Size & LOC Bias`)

- **Descrição do Viés:** Projetos maiores (ex.: 200.000 linhas de código) tendem naturalmente a acumular um número absoluto maior de avisos de manutenibilidade do que micro-repositórios (ex.: 1.500 linhas), mesmo quando possuem melhor engenharia proporcional.
- **Mitigação Implementada:**
  - Métricas de manutenibilidade e defeitos não críticos são ponderadas por densidade normalizada (por KLOC elegível analisado) combinada com limites logarítmicos suaves.
  - Em contrapartida, vulnerabilidades críticas exploráveis (`SQLi`, `CMDi`, `SSRF`, segredos hardcoded) acionam **Travas de Penalidade (*Kill Switches / Penalty Caps*)** independentes do tamanho do repositório, pois uma única falha crítica compromete a segurança de qualquer sistema.

---

## 2. Viés de Profundidade Analítica por Linguagem (`Language Depth Bias`)

- **Descrição do Viés:** O motor nativo do WinHood possui resolução AST + Taint interprocedural completa para TypeScript/JavaScript, enquanto opera em modo estrutural/intraprocedural para Python, Java, Go, C# e Rust. Sem correção, um software em TypeScript poderia sofrer inspeção mais rigorosa do que um software equivalente em outra linguagem.
- **Mitigação Implementada:**
  - Separação explícita entre **Nota Técnica (`technicalScore`)** e **Confiança da Evidência (`evidenceConfidence`)**.
  - O motor de comparabilidade (`BenchmarkMatcher`) verifica a simetria tecnológica dos candidatos e registra alerta de assimetria metodológica quando dois softwares utilizam pilhas com profundidades de análise distintas.
  - Suporte nativo à ingestão padronizada via **SARIF 2.1.0** para complementar a profundidade estática em linguagens compiladas mantendo a rastreabilidade de origem.

---

## 3. Viés de Dados Ausentes (`Missing Data Penalty / Reward Bias`)

- **Descrição do Viés:** Plataformas tradicionais frequentemente convertem uma métrica não coletada (ex.: ausência de relatório LCOV de cobertura de testes ou ausência de benchmark dinâmico) em nota `0.00` (punição injusta por indisponibilidade de ferramenta) ou em `100%` (aprovação falsa por omissão).
- **Mitigação Implementada:**
  - **Regra Estrita de Estados de Medição:** Métricas não medidas recebem o estado formal `NOT_MEASURED` (`null`).
  - **Renormalização Dinâmica de Pesos:** O `scoringEngine` exclui dimensões `NOT_MEASURED` do denominador e renormaliza proporcionalmente os pesos apenas entre as dimensões efetivamente mensuradas (`MEASURED` / `STATIC_DERIVED`), reduzindo simultaneamente o indicador de **Cobertura de Escopo** e **Confiança da Evidência** para impedir que um projeto com poucos dados pareça superior a um projeto amplamente auditado.

---

## 4. Viés de Repetição de Regra Única (`Single-Rule Flooding Bias`)

- **Descrição do Viés:** Uma única convenção de código ou configuração repetida dezenas de vezes em arquivos gerados pode distorcer a pontuação global se cada ocorrência subtrair linearmente pontos da mesma categoria.
- **Mitigação Implementada:**
  - Deduplicação determinística por chave canônica (`filePath:lineNumber:ruleId`) e aplicação de decaimento marginal para ocorrências repetidas da mesma regra de baixa/média severidade, preservando o impacto integral para vulnerabilidades `BLOCKER` e `CRITICAL`.
