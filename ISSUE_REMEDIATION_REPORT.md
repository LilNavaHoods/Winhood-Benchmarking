# Relatório Técnico de Remediação de Issues — WinHood Benchmarking v4.4.0

**Repositório:** `https://github.com/LilNavaHoods/Winhood-Benchmarking.git`  
**Branch:** `main`  
**Versão:** `4.4.0`  
**Commit de Referência da Auditoria:** `143151fedcf1d8f6d3b7c3cc4527ef1b052233e6`  
**Data da Validação Local:** `2026-11-24`  

---

## A. Resumo Executivo

Todas as issues técnicas priorizadas nos Módulos 1, 2, 3 e 4 (`SONAR-001` a `SONAR-004`, `QUALITY-001` a `QUALITY-003`, `CODE-001`, `SEC-001` a `SEC-004`, `CI-001` a `CI-003`, `SUPPLY-001`) e todas as **20 issues abertas** consultadas diretamente na API pública do SonarCloud para o commit de referência `143151fedcf1d8f6d3b7c3cc4527ef1b052233e6` foram remediadas diretamente no código-fonte, acompanhadas de testes automatizados de regressão e sem qualquer redução de limiares de qualidade ou supressões artificiais.

### Impacto Mensurado
- **Confiabilidade & Qualidade Estática:** `tsconfig.json` promovido para `"strict": true` (0 erros em `npm run typecheck`), ESLint 9 configurado (`eslint.config.mjs`) separado do typecheck (0 erros em `npm run lint`), e **100% de aprovação** em `npm test` (128/128) e `npm run test:coverage` (135/135).
- **Cobertura Real (Política Anti-Mock, `c8 + v8-to-istanbul`, `all: true`):**
  - **Núcleo Auditado (6 domínios, 19 arquivos):** `83.98%` Linhas / `90.14%` Funções / `95.72%` Branches (**PASSED**, metas ≥80% / ≥80% / ≥75%).
  - **Motores Críticos:** `src/scoring/` (**100% L / 100% F / 100% B**, antes 94.44% B), `src/evidence/` (**100% L / 100% F / 100% B**), `src/comparability/` (**100% L / 100% F / 98.08% B**).
  - **13 Domínios Oficiais (83 arquivos elegíveis, 0 arquivos não executados):** subiu de ~61% para **71.10% Linhas / 59.53% Funções / 85.82% Branches**, com **12 de 13 domínios** atingindo todas as suas metas individuais (`src/components/` permanece registrado transparentemente em `domainShortfalls` com `50.33%` L em SSR Node, sem mascaramento).
  - **Artefato LCOV:** `coverage/lcov.info` gerado com **733.574 bytes** e validado antes da aprovação do Coverage Gate.
- **Segurança do Backend & Acesso Local-First:**
  - Preservado integralmente o modelo **Acesso Local Livre + TOTP 2FA Opcional (RFC-6238)** em `LOCAL_DESKTOP` / `LOCAL_WEB`, sem login, cadastro, senha, PIN, OAuth, PAT ou Windows Hello.
  - Implementado modo explícito **`REMOTE_DEPLOYMENT` fail-closed** (exige `WINHOOD_REMOTE_API_TOKEN` ≥ 32 chars, comparação em tempo constante via SHA-256 + `crypto.timingSafeEqual`, lockout contra força bruta 5 falhas → HTTP `429`, logs de auditoria estruturados com mascaramento de segredos e restrição de `dataDir` no `/api/health`).
  - Corrigido o conflito de parser JSON global 2MB vs 50MB (`CODE-001`), adicionada validação rigorosa de Base64 e assinatura mágica ZIP e bloqueio fail-closed contra **Zip Slip / Path Traversal** dentro de `extractZipBufferToFilesMap`.
  - Corrigido `trust proxy` para `false` por padrão (`SEC-002`) com validação explícita de hops (`1..10`), `loopback` ou lista IP/CIDR.
- **Distribuição Desktop Windows & Supply Chain:**
  - Corrigida a causa raiz do timeout do instalador Windows (`electron-main.ts` não disparava bootstrap em executáveis empacotados quando `process.argv[1]` era indefinido e ignorava `WINHOOD_DATA_DIR`), com emissão de `runtime-status.json` e diagnóstico completo em `scripts/windows/test-installer-e2e.ps1`.
  - Sincronizado `package-lock.json` (690 pacotes, **0 vulnerabilidades** em `verify-npm-audit.mjs`) e emitido `dist-desktop/provenance-attestation.json` vinculado por SHA-256 ao `build-manifest.json` v2.0.0.

### Itens Pendentes de Ambiente Externo (Registrados com Veracidade)
1. **Re-execução oficial na nuvem SonarCloud (`SONAR-002` / `SONAR-003` / `SONAR-004`):** validado estaticamente e localmente (`lcov.info` = 733 KB, projeto/org verificados na API do SonarCloud), mas a execução remota do workflow `.github/workflows/build.yml` depende de `git push` e do secret `SONAR_TOKEN` no GitHub Actions (**`NOT_VALIDATED`** localmente).
2. **Execução E2E real do Inno Setup em `windows-latest` (`CI-002`):** build desktop (`dist-desktop/*`) e testes unitários de lifecycle (`src/desktop/desktop.test.ts`) validados localmente em Linux; a compilação `ISCC.exe` e o ciclo de 13 passos em Windows dependem do runner `windows-latest` (**`NOT_MEASURED`** localmente).

---

## B. Matriz de Correções

| ID | Severidade | Arquivo(s) Alterado(s) | Problema Original | Correção Implementada | Evidência de Validação | Status |
| :--- | :---: | :--- | :--- | :--- | :--- | :---: |
| **SONAR-001** | P0 (Alta) | `sonar-project.properties` | Arquivo continha apenas `sonar.projectKey=Winhood-Benchmarking` incorreto, sem organização, escopos, exclusões ou LCOV. | Configurado com identificadores reais verificados na API do SonarCloud (`LilNavaHoods_Winhood-Benchmarking`, `lilnavahoods`), separação estrita `sonar.sources` vs `sonar.tests`, exclusões de artefatos/testes e `sonar.javascript.lcov.reportPaths=coverage/lcov.info`. | Validação contra API pública `sonarcloud.io/api/components/show` + grep no workflow. | **FIXED** |
| **SONAR-002** | P0 (Alta) | `.github/workflows/build.yml` | Scanner falhava com `Call to URL [/api/v2/analysis/version] failed: null` por ausência de `sonar.host.url` explícito e versão antiga do scanner. | Atualizado para `SonarSource/sonarqube-scan-action@70bad232...` (v8.5.1), `fetch-depth: 0`, `-Dsonar.host.url=https://sonarcloud.io`, verificação de presença do `SONAR_TOKEN` sem exposição de segredo. | Workflow validado sintática e estruturalmente; execução remota aguarda push + `SONAR_TOKEN`. | **PARTIAL** *(código corrigido; execução remota `NOT_VALIDATED`)* |
| **SONAR-003** | P0 (Alta) | `.github/workflows/build.yml`, `scripts/run-coverage-gate.mjs` | Cobertura não chegava ao SonarCloud (`coverage: NOT REPORTED`) e `passed` era calculado antes da verificação de `lcov.info`. | `run-coverage-gate.mjs` agora valida `coverage/lcov.info` e `coverage/index.html` não vazios **antes** de definir `passed`; `build.yml` executa `npm run test:coverage`, verifica `-s coverage/lcov.info` e repassa o arquivo ao scanner. | `coverage/lcov.info` gerado com `733.574` bytes e validado em `npm run test:coverage`. | **FIXED** *(upload remoto aguarda CI)* |
| **SONAR-004** | P0 (Alta) | `.github/workflows/build.yml`, `src/gate/NewCodeDiffEngine.ts`, `src/execution/SandboxExecutor.ts`, `src/security/KeyManagementService.ts`, `src/analyzers/sca/SbomGenerator.ts`, `src/analyzers/ParserRegistry.ts`, `src/storage/PersistentDatabaseManager.ts`, `scripts/verify-npm-audit.mjs` | Quality Gate SonarCloud em `ERROR` com 20 issues abertas (7 Bugs, 11 Vulnerabilities, 2 Code Smells) e sem `sonarqube-quality-gate-action`. | Todas as 20 issues abertas remediadas diretamente no código (detalhadas na Seção D); adicionado `SonarSource/sonarqube-quality-gate-action@7a5fffe8...` (v1.2.1) com timeout de 300s e enforço final do Coverage Gate. | 20/20 issues corrigidas no código + `typecheck`, `lint`, `npm test` (128/128) e `test:coverage` (135/135) verdes; reavaliação remota do Quality Gate aguarda CI. | **PARTIAL** *(20/20 código corrigido; gate remoto `NOT_VALIDATED`)* |
| **QUALITY-001** | P0 (Alta) | `eslint.config.mjs`, `package.json`, `tsconfig.json`, `server.ts`, `packages/vscode-extension/test/extension.integration.test.ts` | `npm run lint` executava apenas `tsc --noEmit` (sem ESLint real) e `tsconfig.json` não possuía `"strict": true`. | Instalado ESLint 9 + `typescript-eslint` + `eslint-plugin-react-hooks`, criado `eslint.config.mjs` com regras de segurança/qualidade, separado `lint` (`eslint .`) de `typecheck` (`tsc --noEmit`), habilitado `"strict": true` em `tsconfig.json`. | `npm run typecheck` (0 erros) e `npx eslint . --quiet` (0 erros). | **FIXED** |
| **QUALITY-002** | P0 (Alta) | `src/scoring/scoring.test.ts`, `packages/vscode-extension/src/extension.ts`, `packages/vscode-extension/test/extension.integration.test.ts`, `src/execution/coverageEngine.test.ts`, `src/components/uiAndE2e.test.ts`, `src/security/backendHardening.test.ts`, `scripts/run-coverage-gate.mjs` | `src/scoring/` com 94.44% branches (<95%), arquivos não executados nos 13 domínios (~61% L), bug real no Quick Fix SQLi (`$1` não escapado em `extension.ts`). | Criada suíte exaustiva para `src/scoring/` (100% L/F/B), expandidos testes de `SsrfGuard`/`SandboxExecutor`/`CoverageReportParser`, extensão VS Code (e corrigido escape `$$1` no Quick Fix SQLi), `KeyManagementService` (81.83% L) e SSR de todos os 9 módulos/modais UI (0 arquivos não executados nos 83 elegíveis). | `[WinHood Coverage Gate PASSED]`, 135/135 testes, 12/13 domínios acima das metas, 13 domínios em `71.10% L / 85.82% B`. | **FIXED** |
| **QUALITY-003** | P1 (Média) | `README.md` | Badge estático desatualizado (`coverage-96.4%`) e Seções 4/7 descrevendo GitHub OAuth 2.0 + PKCE removido. | Atualizado com badges e tabela fiel ao `coverage/coverage-summary.json` real, comandos separados `typecheck`/`lint`, documentação de Acesso Local Livre + TOTP 2FA Opcional e guia de `REMOTE_DEPLOYMENT`. | Verificação direta contra `coverage/coverage-summary.json` e `.env.example`. | **FIXED** |
| **CODE-001** | P0 (Crítica) | `server.ts`, `src/security/backendHardening.test.ts` | `express.json({ limit: '2mb' })` global interceptava uploads >2MB antes do `heavyUploadJsonParser` (`50mb`) nas rotas de upload/ZIP/SARIF; extrator ZIP não bloqueava Zip Slip (`../../etc/passwd`) de forma fail-closed. | Parser global agora ignora `HEAVY_JSON_UPLOAD_PATHS` (`/api/projects/upload`, `/api/projects/extract-zip`, `/api/analyze/sarif`); adicionada validação estrita de Base64, assinatura mágica ZIP, rejeição fail-closed de Zip Slip (`ZIP_PATH_TRAVERSAL_BLOCKED`) e respostas estruturadas `413 PAYLOAD_TOO_LARGE` / `400 INVALID_JSON_PAYLOAD`. | Testes de regressão em `backendHardening.test.ts` (<2MB, >2MB upload, >2MB ZIP 12 arquivos, 413 rota padrão, JSON/Base64/ZIP inválidos, Zip Slip e path traversal bloqueados). | **FIXED** |
| **SEC-001** | P0 (Crítica) | `server.ts`, `.env.example`, `src/types/benchmark.ts`, `src/security/backendHardening.test.ts` | Ausência de separação formal entre operação local e implantação remota; risco de exposição sem proteção em deploy remoto. | Adicionado `resolveDeploymentMode()` (`LOCAL_DESKTOP` \| `LOCAL_WEB` \| `REMOTE_DEPLOYMENT`). Em modo local preserva 100% acesso livre + TOTP 2FA opcional. Em `REMOTE_DEPLOYMENT` exige `WINHOOD_REMOTE_API_TOKEN` ≥ 32 chars no boot (fail-closed), validação constante `timingSafeEqual` sobre SHA-256, lockout após 5 falhas (HTTP 429) e ocultação de `dataDir` em `/api/health`. | Testes automatizados em `backendHardening.test.ts` (boot recusado sem token, 401 sem Bearer, 201 com Bearer, 429 após 5 falhas, modo local irrestrito preservado). | **FIXED** |
| **SEC-002** | P0 (Alta) | `server.ts`, `.env.example`, `src/security/backendHardening.test.ts` | `app.set('trust proxy', 1)` hardcoded permitia spoofing de `X-Forwarded-For` e bypass de rate limiting em acesso direto. | Criado `resolveTrustProxyConfig()` com padrão `false`; aceita apenas inteiros `1..10`, `'loopback'` ou lista IP/CIDR validada. | Testes em `backendHardening.test.ts` provando que `X-Forwarded-For` forjado é ignorado com `trustProxy: false` (HTTP 429 na 3ª req) e respeitado quando `trustProxy: 1`. | **FIXED** |
| **SEC-003** | P0 (Alta) | `src/security/KeyManagementService.ts`, `src/security/backendHardening.test.ts` | Cobertura incompleta do ciclo de vida do Keystore (rotação `TOKEN_VAULT_AES256`, revogação de chaves, Trust Store Ed25519 e separação de domínios). | Remediadas 2 issues `S4036` no DPAPI PowerShell (`PATH` controlado + executável absoluto) e adicionada suíte completa validando `assertSecretDomainSeparation`, rotação HMAC/Ed25519/TOKEN_VAULT_AES256, `revokeKey`, rejeição de PEM adulterado/revogado e `verifyStrictAdminToken`. | `src/security/` atingiu `81.83% L / 93.24% F / 95.03% B` (PASSED) com 100% dos testes de segurança aprovados. | **FIXED** |
| **SEC-004** | P1 (Média) | `server.ts`, `src/types/benchmark.ts`, `src/security/backendHardening.test.ts` | Logs de auditoria sem campos estruturados de modo/origem/desfecho e sem garantia testada de mascaramento em eventos remotos. | Enriquecido `appendAuditLog` com `maskSecretsInText`, `deploymentMode`, `origin`, `operationType`, `outcome`, `failureReason`, `integrityState` e role `REMOTE_OPERATOR`; validado zero vazamento de tokens brutos nos logs. | Assertivas em `backendHardening.test.ts` comprovando eventos `REMOTE_AUTH_DENIED`, `REMOTE_AUTH_LOCKED`, `REMOTE_WRITE_AUTHORIZED` e ausência de tokens no JSON serializado. | **FIXED** |
| **CI-001** | P0 (Alta) | `.github/workflows/ci-multiplatform.yml`, `scripts/ci-summary.mjs`, `package.json`, `package-lock.json` | Falha na CI Linux por branches em `src/scoring/` (<95%), rótulos obsoletos (OAuth PKCE / TypeScript como lint) e desalinhamento de lockfile após adição do ESLint. | Corrigidos rótulos e etapas em `ci-multiplatform.yml` e `ci-summary.mjs`, sincronizado `package-lock.json` (690 pacotes, zero vulnerabilidades), e `src/scoring/` elevado para 100% L/F/B. | `ci-summary.mjs --self-test` (7/7), `verify-independent-positioning.mjs` (155 arquivos), `verify-npm-audit.mjs` (0 vulns), `test:coverage` PASSED. | **FIXED** |
| **CI-002** | P0 (Crítica) | `electron-main.ts`, `scripts/windows/test-installer-e2e.ps1`, `src/desktop/desktop.test.ts` | Timeout no teste E2E do instalador Windows: `electron-main.ts` não disparava bootstrap em `.exe` empacotado (`process.argv[1]` ausente), ignorava `WINHOOD_DATA_DIR`, e o script PS1 silenciava erros com `catch {}` e assumia porta fixa 3000. | Adicionado `isPackagedElectronMain`, prioridade para `process.env.WINHOOD_DATA_DIR`, emissão/remoção de `logs/runtime-status.json` com porta/URL efetiva e `desktop-bootstrap.log`; reescrito `test-installer-e2e.ps1` com descoberta dinâmica de porta, captura de PID/exitCode/stdout/stderr/bootstrapLog e limpeza em `finally`. | `src/desktop/desktop.test.ts` valida `runtime-status.json`, `LOCAL_DESKTOP` e cleanup; execução real do `.exe`/Inno Setup em `windows-latest` está `NOT_MEASURED` localmente. | **PARTIAL** *(código e testes Linux validados; E2E Windows aguarda runner `windows-latest`)* |
| **SUPPLY-001** | P0 (Alta) | `scripts/verify-npm-audit.mjs`, `scripts/build-desktop.mjs`, `.github/workflows/ci-multiplatform.yml`, `package-lock.json` | `verify-npm-audit.mjs` acionava `S4036` (`execSync` com `PATH` herdado) e `build-desktop.mjs` não gerava atestação de proveniência separada com SHA-256 do manifesto. | Migrado para `execFileSync` com binário `npm` resolvido e `PATH` controlado + detalhamento completo por severidade (`critical/high/moderate/low`); `build-desktop.mjs` agora gera `build-manifest.json` v2.0.0 e `provenance-attestation.json` incluído nos artefatos da CI. | `verify-npm-audit.mjs` PASSED (`ZERO_VULNERABILITIES` 0/0/0/0) e `npm run build:desktop` gerou ambos artefatos com `manifestSha256`. | **FIXED** |
| **CI-003** | P1 (Média) | `.github/workflows/ci-multiplatform.yml`, `.github/workflows/build.yml` | Ações e metadados precisavam de pinning imutável por commit SHA e validação de consistência entre workflows. | Todas as GitHub Actions (`checkout`, `setup-node`, `upload-artifact`, `sonarqube-scan-action`, `sonarqube-quality-gate-action`) pinadas por SHA completo com permissões mínimas (`contents: read`). | Revisão completa de ambos os arquivos YAML em `.github/workflows/`. | **FIXED** |

---

## C. Evidências de Testes

### Comandos Executados e Resultados Reais
| Comando | Resultado | Detalhes Reais |
| :--- | :---: | :--- |
| `npm run check:browser-imports` | **PASSED** | 38 módulos frontend/shared varridos a partir de 36 entrypoints; 0 imports Node.js ou server-only. |
| `npm run typecheck` (`tsc --noEmit`, `strict: true`) | **PASSED** | 0 erros de tipo em todo o repositório. |
| `npx eslint . --quiet` (`npm run lint`) | **PASSED** | 0 erros (warnings de complexidade legada mantidos transparentemente, sem supressões). |
| `node scripts/verify-npm-audit.mjs` | **PASSED** | `ZERO_VULNERABILITIES` (Critical: 0, High: 0, Moderate: 0, Low: 0 \| 690 pacotes auditados). |
| `node scripts/verify-independent-positioning.mjs` | **PASSED** | 155 arquivos varridos, 5/5 cenários self-test, 0 alegações enganosas. |
| `node scripts/ci-summary.mjs --self-test` | **PASSED** | 7/7 cenários de propagação de status verificados. |
| `npm test` | **PASSED** | **128/128 testes aprovados, 0 falhas, 0 pulados.** |
| `npm run test:coverage` | **PASSED** | **135/135 testes aprovados, 0 falhas**; `[WinHood Coverage Gate PASSED]`. |
| `npm run build` | **PASSED** | `dist/index.html` + bundles Vite 8.3.8 gerados em `1.06s`. |
| `npm run build:desktop` | **PASSED** | `dist-desktop/server.mjs`, `electron-main.mjs`, `electron-preload.cjs`, `build-manifest.json` (v2.0.0) e `provenance-attestation.json` (`manifestSha256: 5896c30ae69560a6...`). |

### Cobertura Real por Domínio (`coverage/coverage-summary.json`, `c8 + v8-to-istanbul`, `all: true`)

- **Artefatos Gerados e Verificados:**
  - `coverage/lcov.info`: **733.574 bytes** (não vazio)
  - `coverage/index.html`: **15.992 bytes** (não vazio)
  - Arquivos elegíveis não executados nos 13 domínios: **0 / 83**
- **Consolidado Núcleo Auditado (6 domínios, 19 arquivos):** **83.98% Linhas / 90.14% Funções / 95.72% Branches** — **PASSED**
- **Consolidado 13 Domínios Oficiais (83 arquivos):** **71.10% Linhas / 59.53% Funções / 85.82% Branches**

| Domínio Oficial | Linhas | Funções | Branches | Meta Oficial (L/F/B) | Arquivos c/ 0% | Status Domínio |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `src/scoring/` *(Motor Crítico)* | **100.00%** | **100.00%** | **100.00%** | 95 / 95 / 95 | 0 | **PASSED** |
| `src/evidence/` *(Motor Crítico)* | **100.00%** | **100.00%** | **100.00%** | 95 / 95 / 95 | 0 | **PASSED** |
| `src/comparability/` *(Motor Crítico)* | **100.00%** | **100.00%** | **98.08%** | 95 / 95 / 95 | 0 | **PASSED** |
| `src/analyzers/` | **80.15%** | **85.71%** | **95.54%** | 80 / 80 / 75 | 0 | **PASSED** |
| `src/engine/` | **93.54%** | **94.44%** | **83.48%** | 80 / 80 / 75 | 0 | **PASSED** |
| `src/gate/` | **88.68%** | **95.24%** | **91.35%** | 85 / 85 / 80 | 0 | **PASSED** |
| `src/security/` | **81.83%** | **93.24%** | **95.03%** | 80 / 80 / 75 | 0 | **PASSED** |
| `src/execution/` | **80.33%** | **97.56%** | **96.05%** | 80 / 80 / 75 | 0 | **PASSED** |
| `src/integrations/` | **86.33%** | **91.23%** | **98.02%** | 80 / 80 / 75 | 0 | **PASSED** |
| `src/reports/` | **93.74%** | **100.00%** | **98.51%** | 85 / 85 / 80 | 0 | **PASSED** |
| `src/desktop/` | **81.10%** | **95.00%** | **86.21%** | 80 / 80 / 75 | 0 | **PASSED** |
| `packages/vscode-extension/` | **97.44%** | **100.00%** | **86.32%** | 80 / 80 / 75 | 0 | **PASSED** |
| `src/components/` | **50.33%** | **13.39%** | **45.05%** | 70 / 70 / 65 | 0 | **SHORTFALL (TRANSPARENTE)** *(handlers de clique/DOM aguardam suíte browser Playwright; nenhum arquivo excluído)* |

---

## D. Evidências do SonarCloud

### Baseline Oficial Consultado na API Pública (`https://sonarcloud.io`)
- **Organization:** `lilnavahoods`
- **Project Key:** `LilNavaHoods_Winhood-Benchmarking`
- **Commit Analisado no Baseline:** `143151fedcf1d8f6d3b7c3cc4527ef1b052233e6` (`2026-11-24T21:47:03Z`)
- **Métricas do Baseline:**
  - **Quality Gate (`alert_status`):** `ERROR` (`new_reliability_rating: 4`, `new_security_rating: 3`)
  - **Bugs:** `7` | **Vulnerabilities:** `11` | **Security Hotspots:** `0` | **Code Smells:** `2` (Total: **20 issues abertas**)
  - **Coverage:** `NOT REPORTED` | **Duplicated Lines Density:** `2.2%` | **NCLOC:** `88.825`

### Remediação das 20 Issues Abertas do SonarCloud
| Regra SonarCloud | Quantidade | Arquivo(s) Remediado(s) | Correção Aplicada | Status no Código |
| :--- | :---: | :--- | :--- | :---: |
| `typescript:S2871` (Array `.sort()` sem comparador) | 5 | `src/gate/NewCodeDiffEngine.ts`, `src/analyzers/sca/SbomGenerator.ts`, `src/engine/BenchmarkOrchestrator.ts` e ordenações determinísticas | Comparadores explícitos `(a, b) => a.localeCompare(b)`. | **FIXED** |
| `typescript:S2612` (`chmod` permissivo) | 4 | `src/execution/SandboxExecutor.ts` | Permissões restritas para `0o750` (diretórios) e `0o640` (arquivos). | **FIXED** |
| `typescript:S4036` + `tssecurity:S8705` (execução de `git` com `PATH` herdado / ref não validada) | 4 | `src/gate/NewCodeDiffEngine.ts` | Validação estrita de git ref (`^[A-Za-z0-9._/@~^-]+$`), resolução de binário absoluto (`resolveSafeGitBinary`) e `PATH` fixo controlado. | **FIXED** |
| `typescript:S4036` (`PATH` controlado em DPAPI PowerShell) | 2 | `src/security/KeyManagementService.ts` | Resolução absoluta do executável PowerShell e `PATH` restrito ao `System32`. | **FIXED** |
| `typescript:S8786` (Regex com backtracking potencial / ReDoS) | 2 | `src/analyzers/sca/SbomGenerator.ts`, `src/analyzers/ParserRegistry.ts` | Substituído por varredura linear determinística e regex sem backtracking exponencial. | **FIXED** |
| `typescript:S3923` (Branches idênticos em condicional) | 1 | `src/analyzers/sca/SbomGenerator.ts` | Removida ramificação duplicada preservando semântica exata. | **FIXED** |
| `typescript:S6544` (Uso indevido de Promise em coalescência) | 1 | `src/storage/PersistentDatabaseManager.ts` | Corrigido fluxo assíncrono/síncrono sem coalescer `Promise`. | **FIXED** |
| `javascript:S4036` (`npm audit` via `PATH` herdado) | 1 | `scripts/verify-npm-audit.mjs` | Migrado para `execFileSync` com binário `npm` resolvido e `PATH` controlado. | **FIXED** |

- **Status da Re-execução Remota no SonarCloud:** **`NOT_VALIDATED`** localmente (o ambiente local não possui `SONAR_TOKEN` nem permissão de `git push`). Assim que o commit for enviado à branch `main` com o secret `SONAR_TOKEN` ativo no GitHub, o workflow `.github/workflows/build.yml` executará o scanner oficial contra `https://sonarcloud.io` com `coverage/lcov.info` e validará o Quality Gate automaticamente.

---

## E. Evidências da CI/CD

| Etapa / Job | Ambiente | Status | Evidência |
| :--- | :---: | :---: | :--- |
| Lockfile Integrity (`package-lock.json` sincronizado, sem `bun.lock`) | Linux Local | **PASSED** | `package-lock.json` sincronizado com `package.json` (`4.4.0`, 690 pacotes, `bun.lock` ausente). |
| Independent Positioning (`verify-independent-positioning.mjs`) | Linux Local | **PASSED** | 155 arquivos, 0 violações, 5/5 self-tests. |
| Dependency Audit (`verify-npm-audit.mjs`) | Linux Local | **PASSED** | `ZERO_VULNERABILITIES` (0/0/0/0). |
| Browser-Safe Import Guard (`check:browser-imports`) | Linux Local | **PASSED** | 38 módulos frontend/shared, 0 vazamentos Node.js. |
| Strict TypeScript (`npm run typecheck`) | Linux Local | **PASSED** | `strict: true`, 0 erros. |
| ESLint (`npm run lint`) | Linux Local | **PASSED** | 0 erros em todo o projeto. |
| Frontend Build (`npm run build`) | Linux Local | **PASSED** | `dist/index.html` gerado sem erros. |
| Full Test Suite (`npm test`) | Linux Local | **PASSED** | 128/128 testes aprovados. |
| Coverage Gate & LCOV (`npm run test:coverage`) | Linux Local | **PASSED** | 135/135 testes, Core 83.98% L / 90.14% F / 95.72% B, `lcov.info` = 733 KB. |
| Desktop Bundle + Provenance (`npm run build:desktop`) | Linux Local | **PASSED** | `dist-desktop/*`, `build-manifest.json` v2.0.0, `provenance-attestation.json`. |
| CI Summary Self-Test (`scripts/ci-summary.mjs --self-test`) | Linux Local | **PASSED** | 7/7 cenários de propagação aprovados. |
| Windows Packaging & Inno Setup E2E (`windows-desktop-validation`) | Runner `windows-latest` | **`NOT_MEASURED`** *(local)* | Correções aplicadas em `electron-main.ts`, `test-installer-e2e.ps1` e `ci-multiplatform.yml`; aguarda execução no runner Windows do GitHub Actions. |
| SonarCloud Cloud Scan & Quality Gate (`build.yml`) | Runner `ubuntu-latest` + `sonarcloud.io` | **`NOT_VALIDATED`** *(local)* | `sonar-project.properties` e `build.yml` corrigidos; aguarda push + `SONAR_TOKEN` no repositório GitHub. |

---

## F. Pendências (Dependentes de Infraestrutura Externa)

1. **Execução remota do SonarCloud (`build.yml`):** realizar `git push` para `main` (ou abrir PR) com o secret `SONAR_TOKEN` configurado no repositório GitHub para confirmar a passagem do Quality Gate na nuvem (`0` Bugs, `0` Vulnerabilities, `0` Code Smells e ingestão de `coverage/lcov.info`).
2. **Validação real do Instalador Windows (`windows-desktop-validation`):** executar o workflow `.github/workflows/ci-multiplatform.yml` no runner `windows-latest` para validar `npm run pack:win`, compilação `ISCC.exe` (`WinHood-Benchmarking-Setup.exe`) e o ciclo E2E de 13 etapas com diagnóstico (`release-windows/windows-installer-e2e-report.json`).
3. **Evolução futura da cobertura interativa de UI (`src/components/`):** atualmente em `50.33%` linhas via SSR Node (zero arquivos fora do denominador); atingir ≥70% em funções/branches de componentes React interativos requer acionar cliques/formulários via Playwright em ambiente com navegador headless.
