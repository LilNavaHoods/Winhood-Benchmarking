# Relatório de Validação de Qualidade de Software e Motores Analíticos (`QUALITY_VALIDATION_REPORT.md`)

**Data de Execução:** 2026-11-17  
**Versão:** `4.4.0`

---

## 1. Validação dos Motores Analíticos (SAST, Taint, AST, Segredos e SCA)

| Motor Analítico | Escopo Validado | Evidência Técnica | Estado |
|---|---|---|---|
| **ParserRegistry Multi-Linguagem** | Distinção explícita entre `FULL_AST` (TS/JS/TSX/JSX), `STRUCTURAL_AST` (Python, Java, Go, Rust, C#, SQL) e `PARTIAL_RECOVERY`. | `src/analyzers/ParserRegistry.ts` (`getLanguageAnalyticalCapabilities`) e rebaixamento automático de confiança `HIGH` para `MEDIUM` em `PARTIAL_RECOVERY`. | **VALIDADO** |
| **TaintAnalyzer Contextual** | Rastreamento Fonte → Propagação → Sanitização Contextual → Sink em SQL (`CWE-89`), Comando (`CWE-78`), XSS (`CWE-79`), Path Traversal (`CWE-22`), SSRF (`CWE-918`) e Deserialização (`CWE-502`). | `src/analyzers/taint/TaintAnalyzer.ts`: `encodeURIComponent` não neutraliza SQL Injection, mas `parseInt`/`Number`/prepared statements neutralizam. | **VALIDADO** |
| **SecretDetector** | Detecção determinística por prefixo criptográfico, entropia de Shannon $\ge 4.15$, exclusão de placeholders (`EXAMPLE`, `YOUR_API_KEY`, `<token>`) e redação obrigatória (`redactSecret`). | `src/analyzers/secrets/SecretDetector.ts` validado contra falsos positivos em arquivos `.env.example` e documentação. | **VALIDADO** |
| **SCA & Multi-Lockfile SBOM** | Extração direta e transitiva em `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` e `Cargo.lock`; exportação CycloneDX 1.5 e SPDX 2.3; proveniência estrita de licenças (`NOASSERTION`). | `src/analyzers/sca/SbomGenerator.ts` e `src/analyzers/sca/ScaCorrelator.ts` (`validateSbomBundle` e `advisoryFeedMetadata`). | **VALIDADO** |

---

## 2. Validação de Reprodutibilidade Determinística e Comparabilidade

1. **Determinismo Bit-a-Bit:**
   - Execuções repetidas com o mesmo `deterministicTimestamp` sobre os mesmos artefatos de entrada produzem `ScoreCard`, `EvidenceChain` e `SignedEvidenceManifest` idênticos.
2. **Comparabilidade Bimodal (`SAME_ENGINE` e `CROSS_TOOL`):**
   - Pares intraclasse de mesma categoria e cobertura compatível recebem `STRICTLY_COMPARABLE`.
   - Pares avaliados por motores distintos sobre o mesmo commit recebem `QUALIFIED_COMPARISON` com ressalvas explícitas.
   - Pares com categorias incompatíveis ou cobertura insuficiente recebem `NOT_COMPARABLE` e bloqueiam a proclamação de vencedor (`winnerSoftwareId = null`).
3. **Quality Gates com Três Níveis (`REQUIRED`, `OPTIONAL`, `INFORMATIVE`):**
   - Condições `REQUIRED` com métrica `NOT_MEASURED` resultam em `INCONCLUSIVE`.
   - Condições `OPTIONAL` com métrica `NOT_MEASURED` registram ressalva (`APPROVED_WITH_RESERVATIONS`) sem invalidar o Gate.

---

## 3. Autoauditoria do Próprio Repositório WinHood

O WinHood executa sua própria suíte de análise estática, segredos, acoplamento arquitetural e proveniência sobre seu código-fonte de produção (`src/`, `server.ts`, `package.json`, `README.md`):
- **Achados `BLOCKER` ou `CRITICAL`:** `0`
- **Score Global Auditado:** $\ge 4.40 / 5.00$
- **Decisão do Quality Gate:** `APPROVED` (Evidências assinadas e verificadas pelo Trust Store Ed25519).
