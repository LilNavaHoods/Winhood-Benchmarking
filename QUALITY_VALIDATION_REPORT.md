# Relatório de Validação de Qualidade de Software e Motores Analíticos (`QUALITY_VALIDATION_REPORT.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + unificação de Quality Gate e Comparabilidade
- **Ambiente:** Linux x64, `Node.js v22.23.2`
- **Comandos executados:** `npm test` (`102/102 PASS`), `npm run test:golden` (`7/7 PASS`), `npm run test:coverage` (`111/111 PASS`)
- **Estado de validação:** `VALIDATED`

---

## 1. Validação dos Motores Analíticos e Contratos Críticos

| Motor / Subsistema | Implementação e Evidência Verificada | Cobertura c8 (`all: true`) | Estado |
|---|---|---|---|
| **Scoring Determinístico (`src/scoring/index.ts`)** | Normalização proporcional sobre dimensões efetivamente medidas (`MEASURED` / `STATIC_DERIVED`), exclusão de `NOT_MEASURED` sem fabricar zero, e kill-switch em `2.20` quando há achado crítico confirmado ou segredo exposto. | `100% L / 100% F / 100% B` | `VALIDATED` |
| **Proveniência e Confiança de Evidência (`src/evidence/`)** | Cadeia de hashes SHA-256, assinatura Ed25519 verificada contra `trust-store.json` externo e rebaixamento automático para `LOW` / `INCONCLUSIVE` se a assinatura falhar. | `100% L / 100% F / 100% B` | `VALIDATED` |
| **Comparabilidade A/B (`src/comparability/index.ts`)** | Exige `ComparabilityManifest` completo com digests SHA-256 (`configHashSha256`, `weightsHashSha256`, `eligibleFilesScopeHash`, `taxonomyMappingSha256`); rejeita flags booleanas soltas (`sameCommitVerified` / `normalizedTaxonomyApplied`) sem prova documental no manifesto. | `100% L / 100% F / 98.08% B` | `VALIDATED` |
| **Quality Gate Unificado (`src/gate/QualityGateEngine.ts` & `scoringEngine.ts`)** | Remoção integral de `fudgeFactorApplied` para changesets `<20` linhas; contrato compartilhado entre `QualityGateEngine.evaluate()`, `evaluateFromRun()` e `calculateDeterministicScoreCard()` validado nos 9 cenários obrigatórios. | `89.93% L / 93.75% F / 98.28% B` | `VALIDATED` |
| **Analyzers SAST, Taint, Segredos, IaC & SCA (`src/analyzers/`)** | `ParserRegistry` (`FULL_AST`, `STRUCTURAL_AST`, `PARTIAL_RECOVERY`), `TaintAnalyzer` contextual, `SecretDetector` (entropia $\ge 4.15$ + redação), `SbomGenerator` (7 formatos de lockfile + `NOASSERTION`). | `86.34% L / 89.87% F / 97.47% B` | `VALIDATED` |
| **Exportador de Relatórios (`src/reports/`)** | Exportação determinística em PDF 1.4 assinado, SARIF 2.1.0, HTML5 offline (CSP estrito, zero URLs externas) e JSON assinado. | `96.21% L / 100% F / 99.20% B` | `VALIDATED` |

---

## 2. Determinismo Bit-a-Bit e Dogfooding Local

- **Determinismo CLI:** Duas execuções consecutivas de `./node_modules/.bin/tsx cli/winhood-cli.ts analyze --path ./src/analyzers --deterministic --name WinHoodAnalyzers` produzem saída idêntica byte a byte.
- **Extensão VS Code (`packages/vscode-extension`):** Suíte de integração `extension.integration.test.ts` (`2/2 PASS`) valida diagnósticos SARIF, Hover Markdown, Quick Fix determinístico e fallback automático para CLI offline.
