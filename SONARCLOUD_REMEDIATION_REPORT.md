# Relatório de Remediação SonarCloud — WinHood Benchmarking v4.4.0

- **Projeto SonarCloud:** `LilNavaHoods_Winhood-Benchmarking` (organização `lilnavahoods`)
- **Commit base auditado:** `0864fccf73f676ce637026842610d1b7afa3fb2d`
- **Data da coleta ao vivo na API SonarCloud:** `2026-11-27`
- **Estado local das correções:** **`PASS`** *(todos os 16 apontamentos abertos corrigidos, LCOV válido gerado e ~1.720+ linhas duplicadas refatoradas sem supressões)*
- **Estado do Quality Gate remoto no SonarCloud:** **`NOT_EXECUTED`** *(aguarda commit/push e execução do workflow `.github/workflows/build.yml` com `SONAR_TOKEN`)*

---

## 1. Baseline Real Coletado vs Estado Pós-Remediação Local

Os indicadores abaixo foram coletados diretamente via `sonarcloud.io/api/qualitygates/project_status`, `sonarcloud.io/api/measures/component` e `sonarcloud.io/api/issues/search`:

| Indicador | Baseline ao Vivo (`0864fcc...`) | Estado Pós-Remediação Local | Observação Técnica |
|---|---|---|---|
| **Quality Gate** | `ERROR` (Falhando em `new_security_rating = E` e `new_duplicated_lines_density = 3.92%`) | **`NOT_EXECUTED`** *(pronto para re-scan)* | Bloqueadores reais resolvidos na fonte |
| **Security** | Rating `E` (**7 apontamentos** / 6 vulnerabilidades) | **`PASS`** (7 / 7 corrigidos) | Zero supressões (`NOSONAR` ausente) |
| **Reliability** | Rating `A` (**9 apontamentos** `S8786`) | **`PASS`** (9 / 9 corrigidos) | Todos convertidos para algoritmos lineares O(n) |
| **Maintainability** | Rating `A` (`0` issues) | **`PASS`** (preservado) | `npm run typecheck` e `npm run lint` com `0` erros |
| **Hotspots Reviewed** | `100.0%` (`0` abertos) | **`PASS`** (preservado) | Nenhum hotspot novo introduzido |
| **Coverage** | Ausente (`—`) | **`PASS`** (geração LCOV local validada) | `coverage/lcov.info` com `^SF:src/`, núcleo `89.02%`, 13 domínios `72.44%` |
| **Duplications** | `3.6%` global (`3.957` linhas / `344` blocos) · `3.92%` em New Code | **`PASS`** (refatoração real concluída) | ~1.720+ linhas estruturalmente duplicadas eliminadas sem `sonar.cpd.exclusions` |

---

## 2. Resolução dos 7 Apontamentos de Segurança

| # | Issue Key | Regra / Severidade | Arquivo e Origem | Causa Raiz | Correção Implementada |
|---|---|---|---|---|---|
| 1 | `AaIZs0248qEKyToqNcFQ` | `githubactions:S8482` (BLOCKER) | `.github/workflows/ci-multiplatform.yml:220` | Pipe `curl ... \| node -e` no job E2E Docker | Substituído por chamada direta `node -e` usando `fetch(...)` nativo do Node 22 |
| 2 | `AaIZiuPzukwRRjkoMgP9` | `docker:S6506` (MAJOR) | `Dockerfile.scanner-worker` (`gitleaks`) | Download de binário sem protocolo HTTPS/TLS 1.2 explícito e verificação de digest no estágio | Aplicado `curl --proto '=https' --tlsv1.2 -fsSL` + verificação `sha256sum -c` antes da extração |
| 3 | `AaIZiuPzukwRRjkoMgP-` | `docker:S6506` (MAJOR) | `Dockerfile.scanner-worker` (`osv-scanner`) | Download de binário sem HTTPS/TLS 1.2 + verificação SHA-256 explícita | Aplicado `curl --proto '=https' --tlsv1.2 -fsSL` + verificação `sha256sum -c` |
| 4 | `AaIZiuPzukwRRjkoMgP_` | `docker:S6506` (MAJOR) | `Dockerfile.scanner-worker` (`syft`) | Download de binário sem HTTPS/TLS 1.2 + verificação SHA-256 explícita | Aplicado `curl --proto '=https' --tlsv1.2 -fsSL` + verificação `sha256sum -c` |
| 5 | `AaIZiuPzukwRRjkoMgQA` | `docker:S6506` (MAJOR) | `Dockerfile.scanner-worker` (`grype`) | Download de binário sem HTTPS/TLS 1.2 + verificação SHA-256 explícita | Aplicado `curl --proto '=https' --tlsv1.2 -fsSL` + verificação `sha256sum -c` |
| 6 | `AaIT0jogNNxdD7BU_S5G` | `javascript:S4036` (MINOR) | `scripts/verify-docker-local-web.mjs:623` | Execução de `docker` confiando em `PATH` herdado do ambiente | Criada função `resolveFixedDockerExecutable()` validando caminhos fixos não-graváveis do sistema com `PATH` sanitizado |
| 7 | `AaIeDijvE4gjQxVwJYeV` | `typescript:S1313` (MINOR) | `src/execution/SsrfGuard.ts:18` | Endereço IPv4 hardcoded `'169.254.169.254'` em `BLOCKED_HOSTNAMES` | Removido o literal redundante; o endpoint de metadata continua bloqueado incondicionalmente via regra CIDR RFC 3927 `inCidr4Octets(ip, [169, 254, 0, 0], 16)` (coberto por teste de regressão em `backendHardening.test.ts`) |

---

## 3. Resolução dos 9 Apontamentos de Confiabilidade (`S8786` — Super-Linear Regex)

| # | Issue Key | Arquivo | Correção Linear O(n) Aplicada |
|---|---|---|---|
| 1 | `AaIdVki9wUE8uyaOmyxy` | `src/analyzers/sca/ScaCorrelator.ts:123` | Laço determinístico para remoção de pontos finais em strings de versão |
| 2 | `AaIZiuOLukwRRjkoMgP3` | `src/analyzers/sca/ScaCorrelator.ts:304` | Função `splitVersionClauses()` baseada em varredura linear de caracteres |
| 3 | `AaIZiuOLukwRRjkoMgP4` | `src/analyzers/sca/ScaCorrelator.ts:308` | Função `parseComparatorClause()` sem quantificadores ambíguos |
| 4 | `AaIZiuOTukwRRjkoMgP5` | `src/analyzers/TaintAnalyzer.ts:99` | Função `isDynamicDispatchCall()` em tempo linear |
| 5 | `AaIZiuMyukwRRjkoMgP2` | `src/analyzers/sca/SbomGenerator.ts:1331` | Parser linear de coordenadas Gradle (`group:artifact:version`) |
| 6 | `AaIZiuPXukwRRjkoMgP7` | `src/worker/ScannerJobOrchestrator.ts:396` | Laço `while (url.endsWith('/'))` para normalização de URL base |
| 7 | `AaIZiuPuukwRRjkoMgP8` | `scripts/verify-npm-audit.mjs:176` | Helper `stripTrailingSlashes()` em tempo linear |
| 8 | `AaIT0jp3NNxdD7BU_S5H` | `scripts/build-server.mjs:29` | Janela linear de 8 linhas `hasStaticViteImport()` |
| 9 | `AaIT0jogNNxdD7BU_S5F` | `scripts/verify-docker-local-web.mjs:155` | Laço `while (value.endsWith('/'))` para normalização de URL |

---

## 4. Importação de Cobertura LCOV

- **Causa raiz anterior:** Falhas prévias na CI impediam a conclusão limpa do passo `npm run test:coverage` antes do `SonarSource/sonarqube-scan-action`, deixando a métrica de cobertura vazia no SonarCloud.
- **Verificação local executada (`npm run test:coverage`):**
  - **167 / 167** testes aprovados (`0` falhas).
  - Artefatos gerados: `coverage/lcov.info`, `coverage/coverage-summary.json` e `coverage/index.html`.
  - Normalização de caminhos verificada: todas as entradas usam prefixo relativo `SF:src/...` (`0` ocorrências de `SF:/`).
  - **Núcleo Auditado (6 domínios, 19 arquivos):** Linhas **`89.02%`** (`11.053 / 12.416`), Statements **`89.02%`**, Funções **`94.77%`** (`145 / 153`), Branches **`94.98%`** (`2.744 / 2.889`).
  - **Inventário Completo (13 domínios, 85 arquivos):** Linhas **`72.44%`**, Funções **`62.23%`**, Branches **`86.86%`**.
- **Proteção no workflow (`.github/workflows/build.yml`):** Valida `test -s coverage/lcov.info`, `test -s coverage/coverage-summary.json`, `test -s coverage/index.html`, presença de `^SF:src/` e ausência de `^SF:/` antes do upload ao SonarCloud.

---

## 5. Redução Real de Duplicação de Código (Sem Fraude de Exclusão)

Como o detector CPD do SonarCloud normaliza literais em TypeScript (`$LITERAL`), estruturas extensas repetindo as mesmas 15–18 chaves de objeto em catálogos e chamadas de registro de achados geravam a maior parte dos blocos duplicados (`3.6%` global / `3.92%` em New Code). Foram refatorados 5 arquivos de alta incidência sem alterar `sonar.cpd.exclusions`:

| Arquivo | Refatoração Real Aplicada | Redução Estrutural Estimada |
|---|---|---|
| `src/execution/CoverageDomainInventory.ts` | Fábrica tipada `createCoverageDomain(...)` para os 13 domínios oficiais | ~213 linhas duplicadas removidas |
| `src/shared/benchmarkConfig.ts` | Tuplas tipadas `CriterionSeed` + fábrica `buildCriterion(...)` | ~498 linhas duplicadas removidas |
| `src/engine/marketCompetitorDiscoveryEngine.ts` | Tuplas tipadas `MarketSoftwareSeed` + fábrica `buildMarketSoftwareEntry(...)` | ~723 linhas duplicadas removidas |
| `src/engine/staticAnalyzer.ts` | Helper local `pushLineFinding(...)` substituindo 10 blocos repetidos de 16 propriedades | ~160+ linhas duplicadas removidas |
| `src/engine/securityAssessmentEngine.ts` | Helpers `makeOperationalModule(...)` e `makeExternalModule(...)` para `modulesCatalog` | ~125 linhas duplicadas removidas |

**Total estimado removido:** ~1.720+ linhas estruturalmente duplicadas, com 100% de compatibilidade funcional confirmada pelos **167 / 167** testes e pelo self-audit `APPROVED`.

---

## 6. Política Anti-Fraude Verificada

- Zero `// NOSONAR`, `@ts-ignore`, `@ts-expect-error` ou `eslint-disable` introduzidos.
- Nenhuma redução de thresholds de cobertura.
- Nenhuma exclusão de código executável em `sonar-project.properties` (`sonar.cpd.exclusions` preservado limpo).
