# Integração de Remediação Autônoma Supervisionada (`AUTONOMOUS_REMEDIATION.md`)

Este documento descreve o subsistema de validação de correções automatizadas e branches isoladas de remediação do **WinHood Benchmarking**.

---

## 1. Fluxo de Remediação com Aprovação Humana Obrigatória

1. **Isolamento de Branch:** Qualquer sugestão de correção gerada por Code Actions determinísticas ou motores de patch opera exclusivamente em uma branch dedicada de trabalho (`winhood/remediation-*`), nunca alterando silenciosamente a branch principal nem os arquivos originais do software auditado.
2. **Revalidação Determinística:** O patch proposto é reavaliado pelo motor AST + Taint + SCA do WinHood para comprovar que o achado alvo foi eliminado sem introduzir novas regressões ou quebrar o Quality Gate.
3. **Governança e Revisão Humana:** Nenhuma alteração de código é promovida sem aprovação humana explícita registrada na trilha de auditoria (`HUMAN_APPROVAL_REQUIRED`).
