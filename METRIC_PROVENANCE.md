# Proveniência de Métricas, Evidências Criptográficas e Estados de Medição

## 1. Estados Formais de Medição
Toda métrica e indicador no WinHood preserva seu estado real desde a coleta até a interface e relatórios exportados:
- `MEASURED` — Medido diretamente por execução real ou retornado pela API oficial.
- `STATIC_DERIVED` — Derivado deterministicamente da AST/análise estática sobre o código-fonte real ingerido.
- `IMPORTED` — Importado de relatório externo verificável (SARIF 2.1.0, LCOV, JaCoCo, Cobertura, JUnit).
- `NOT_MEASURED` — Métrica não coletada ou ausente na resposta da API (exibida como `NOT_MEASURED`, nunca `0` ou `100`).
- `NOT_COMPUTED` — Condição ou Quality Gate ainda não computado pelo servidor.
- `NOT_SUPPORTED` — Funcionalidade não suportada pela edição/linguagem alvo.
- `API_ERROR` / `FAILED` — Falha de comunicação ou erro HTTP na coleta.
- `PARTIAL` — Coleta parcial (ex.: paginação interrompida após a primeira página).

## 2. Separação entre Métricas de Cobertura
O WinHood nunca trata diferentes tipos de cobertura como equivalentes:
- **Cobertura de Ingestão (`filesReceived / filesDiscovered`)**: percentual de arquivos do repositório ingeridos.
- **Cobertura de Análise Estática (`filesAnalyzed / eligibleFiles`)**: percentual de arquivos elegíveis submetidos ao parser AST.
- **Cobertura de Testes (`coverage`, `line_coverage`, `branch_coverage`)**: obtida exclusivamente de relatórios reais de execução de testes (`CoverageReportParser.ts` nos formatos abertos LCOV, Cobertura XML e JaCoCo XML).

## 3. Cadeia de Evidências e Assinatura Criptográfica
Cada `BenchmarkRun` gera:
- Cadeia encadeada de evidências (`evidenceChain`) onde cada elo contém `previousChainHash` e `chainHash` (SHA-256).
- Manifesto assinado com **HMAC-SHA256** e assinatura assimétrica **Ed25519** (`KeyManagementService.ts`), verificável via `POST /api/runs/:runId/verify-manifest`.
