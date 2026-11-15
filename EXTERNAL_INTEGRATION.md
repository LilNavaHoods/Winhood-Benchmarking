# Interoperabilidade com Padrões Abertos (`EXTERNAL_INTEGRATION.md`)

O **WinHood Benchmarking** opera de forma totalmente autônoma para análise estática (AST), fluxo de dados (Taint Analysis), detecção de segredos, análise de infraestrutura como código (IaC), composição de software (SCA), geração de SBOM e decisão de Quality Gate.

Para ambientes que desejam consolidar evidências adicionais em uma única trilha auditável, o WinHood oferece interoperabilidade nativa baseada exclusivamente em **padrões abertos**.

---

## 1. Padrões Abertos Suportados

1. **OASIS SARIF 2.1.0 (`Static Analysis Results Interchange Format`):**
   - Importação e exportação bidirecional via `SarifCodec` (`src/analyzers/SarifCodec.ts`).
   - Qualquer relatório produzido por **ferramentas que exportam SARIF 2.1.0** pode ser ingerido via CLI (`winhood sarif-import --input resultado.sarif`) ou API REST (`POST /api/external-reports/import`).
   - Todo achado importado recebe identificação explícita de proveniência (`EXTERNAL_TEST_REPORT_IMPORTED`) e hash SHA-256 do documento de origem, jamais sendo confundido com métricas calculadas nativamente pelo motor do WinHood (`WINHOOD_NATIVE`).
2. **OWASP CycloneDX 1.5 & Linux Foundation SPDX 2.3:**
   - Geração e verificação de inventários de dependências (SBOM) assinados com `HMAC-SHA256` e `Ed25519`.
3. **MITRE CWE, FIRST CVSS v3.1/v4.0, EPSS & CISA KEV:**
   - Correlação padronizada de fraquezas e vulnerabilidades com priorização por probabilidade de exploração.
4. **Cobertura LCOV & Cobertura XML:**
   - Ingestão de relatórios de cobertura gerados por executores de testes automatizados (`src/execution/CoverageReportParser.ts`), mantendo separadas a cobertura de linhas, cobertura de branches e cobertura de escopo estático.

---

## 2. Isolamento e Segurança na Ingestão Externa

- **Validação de Schema e Limites:** Arquivos importados passam por verificação de tamanho, estrutura JSON e sanitização de caminhos relativos (prevenção de Path Traversal).
- **Proteção SSRF (`SsrfGuard`):** Conectores HTTP e webhooks bloqueiam endereços de loopback, redes privadas RFC 1918, endereços link-local (`169.254.169.254`) e redirecionamentos não autorizados.
