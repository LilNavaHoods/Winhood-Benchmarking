# GITAR_INTEGRATION.md — Revisão de Código Assistida por IA e Remediação de Falhas de CI (Gitar AI)

## 1. Documentação Oficial
- https://docs.gitar.ai/introduction
- https://docs.gitar.ai/llms.txt
- https://docs.gitar.ai/api-reference/overview

## 2. Separação Arquitetural entre SonarQube e Gitar AI
- **SonarQube Community Build:** Motor determinístico de análise estática de qualidade, segurança, complexidade, duplicação e Quality Gates.
- **Gitar AI:** Agente complementar de revisão de Pull Requests / Merge Requests e diagnóstico de falhas de pipelines de CI (`GitHub Actions`, `GitLab CI`, `Bitbucket Pipelines`, `Azure DevOps Pipelines`).
- Os achados do Gitar AI são apresentados na seção dedicada **`AI CODE REVIEW & REMEDIATION`** e **nunca são somados silenciosamente** à pontuação nativa de qualidade do SonarQube. Quando um achado do Gitar aponta para a mesma linha/regra já identificada pelo SonarQube, o `GitarReviewMapper` registra a correlação (`deduplicatedWithSonarIssueKey`) evitando dupla contagem.
- Quando a conta Gitar não está configurada, o sistema exibe estritamente `NOT_CONFIGURED` e não simula análises de IA.

## 3. Segurança das Alterações Propostas (`src/integrations/gitar/`)
Como o Gitar pode propor patches de código, a plataforma impõe travas rígidas de segurança:
1. `allowDirectModificationOfOriginalFiles: false` — Os arquivos originais dos softwares A e B jamais são alterados diretamente.
2. `isolatedWorkingBranchPrefix: "gitar/remediation-isolated-*"` — Toda sugestão de correção fica isolada em uma branch/cópia de trabalho separada, preservando o commit original.
3. `autoApplyFixes: false`, `autoApprovePr: false`, `autoMergePr: false` — Aplicação, aprovação e merge automáticos são desabilitados por padrão.
4. `requireHumanApprovalBeforeApply: true` — Exibe o diff **Antes / Depois** na interface e exige clique explícito de aprovação humana antes de validar a correção e re-executar os testes automatizados.
