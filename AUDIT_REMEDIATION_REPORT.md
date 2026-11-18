# Relatório de Auditoria Técnica e Remediação — WinHood Benchmarking v4.4.0

- **Versão do WinHood:** `4.4.0`
- **Commit base auditado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` (pós-run CI `44141919950`, com remediações subsequentes aplicadas neste workspace)
- **Ambiente de verificação local:** Container Linux (`linux x64`), `Node.js v22.23.2`, `npm 10.9.8`
- **Ferramentas utilizadas:** `tsc --noEmit` (`typescript@5.9.3`), `tsx --test` (`node:test`), `c8@10.1.3` + `v8-to-istanbul`, `npm audit`, `esbuild@0.28.2`, `vite@8.3.8`, `scripts/verify-independent-positioning.mjs`, `scripts/verify-npm-audit.mjs`, `scripts/ci-summary.mjs`
- **Estado de validação global local:** `PARTIALLY_VALIDATED` *(validações locais Linux e Full-Stack aprovadas; execução remota em runners `ubuntu-latest` + `windows-latest` do GitHub Actions e testes manuais presenciais WCAG permanecem `NOT_VALIDATED` neste container)*

---

## 1. Sumário Executivo

Esta revisão da auditoria v4.4.0 corrige os achados remanescentes identificados após o commit `d382a4e96a0481cba80f005790ab65100dfc5ae4` e a execução de CI `44141919950`:
1. **Desbloqueio da CI Linux (`positioning`) e Windows (`lint`):** Substituição da verificação literal de marca por verificador semântico (`scripts/verify-independent-positioning.mjs`) e resolução do erro `@typescript/typescript-win32-x64` com `typescript@5.9.3` (JS puro) + CI multi-job determinística com agregação real (`scripts/ci-summary.mjs`).
2. **Governança honesta de vulnerabilidades NPM (`npm audit`):** Redução de **11 para 5** advisories high-severity; os 5 remanescentes são exclusivamente da cadeia build-time `picomatch <= 4.0.7` (`GHSA-fc5q-39xc-vjpf`) via `vite@8.3.8`, governados com prazo e controles compensatórios em `security/npm-audit-exceptions.json` (**0 vulnerabilidades não aprovadas**).
3. **Cobertura V8 convencional via `c8` + `v8-to-istanbul` (`all: true`):** Inventário único de 13 domínios (`src/execution/CoverageDomainInventory.ts`) sem listas duplicadas e com separação estrita entre `testCoverage`, `ingestionCoverage` e `analysisCoverage`. Os 3 motores críticos (`src/scoring`, `src/evidence`, `src/comparability`) atingem `100% / 100% / >=98.08%`, e o núcleo de 6 domínios auditados atinge `88.47% L / 92.56% F / 97.74% B`, mantendo visível o déficit real dos domínios UI/desktop/VS Code (`61.02% L` nos 13 domínios).
4. **Keystore `PRODUCTION_SECURE` Fail-Closed:** Remoção do fallback silencioso para `.kek` em `PRODUCTION_SECURE`, segregação estrita de segredos (`WINHOOD_KEYSTORE_MASTER_SECRET` separado de `SONAR_SECRET_SALT`), Trust Store Ed25519 isolado em `trust-store.json` e documentação honesta dos limites do contador monotônico local.
5. **UI Honesta & Suíte E2E de 10 Fluxos:** Substituição de valores sintéticos na interface (`DashboardModule.tsx`, `SonarDockerCloudHubModule.tsx`, `ToolsAndIntegrationsModule.tsx`, `HardwareAndDisplayBenchmarkModule.tsx`) por `NOT_MEASURED` / `N/A` quando ausentes, além da suíte automatizada `src/components/uiAndE2e.test.ts` (SSR + 10 fluxos HTTP reais).

---

## 2. Matriz Atualizada de Achados (`AUD-01` a `AUD-10`)

| ID | Domínio | Causa Raiz Confirmada | Remediação Aplicada e Evidência | Estado |
|---|---|---|---|---|
| **AUD-01** | Supply Chain & NPM | `bun.lock` conflitante + 11 advisories (`electron-builder`, `node-gyp`, `picomatch`). | `bun.lock` ausente, `package-lock.json` sincronizado, `electron-builder@^26.18.0` / `electron@^45.3.3` eliminam 6 advisories; 5 restantes (`picomatch <= 4.0.7`) governados em `security/npm-audit-exceptions.json` (`verify-npm-audit.mjs` PASS). | `VALIDATED` (local) / `PARTIALLY_VALIDATED` (CI remota pendente) |
| **AUD-02** | Cobertura de Testes | Script customizado anterior substituído por motor convencional + transparência nos 13 domínios. | `c8@10.1.3` + `v8-to-istanbul` (`all: true`) a partir de `OFFICIAL_13_COVERAGE_DOMAINS`; núcleo 6 domínios `88.47% L / 92.56% F / 97.74% B`, motores críticos `>=98.08%`, 13 domínios `61.02% L` com déficits declarados. | `VALIDATED` |
| **AUD-03** | Rastreabilidade de Ferramentas | Timestamps e códigos de saída padrão pré-preenchidos antes da execução real. | `lastExecutionAt = null`, `lastExitCode = null`, `integrationType`, `readinessState` e `resultCompleteness` validados em `analyzer.test.ts`. | `VALIDATED` |
| **AUD-04** | Keystore & Trust Store | Fallback `.kek` em produção, reutilização de `SONAR_SECRET_SALT` e Trust Store embutido. | `PRODUCTION_SECURE` exige DPAPI / macOS Keychain / Linux Secret Service / `WINHOOD_KEYSTORE_MASTER_SECRET`; Trust Store isolado em `trust-store.json`; `test:security` 23/23 PASS. | `VALIDATED` (Linux/env/DPAPI simulado) / `PARTIALLY_VALIDATED` (DPAPI nativo Windows em CI) |
| **AUD-05** | Autenticação, Scrypt & MFA | Parâmetros Scrypt `N=16384` e lacunas de matriz E2E TOTP/QR/downgrade. | Migração `scrypt:N=32768,r=8,p=1` com proteção contra downgrade e preservação de arquivo em falha de escrita (`test:security` teste #23 PASS). | `VALIDATED` |
| **AUD-06** | Golden Dataset & Estatística | Separação incompleta e nomenclatura imprecisa de independência externa. | Split formal em 3 conjuntos (`DEVELOPMENT` N=4, `REGRESSION` N=26, `INTERNAL_HOLDOUT` N=18), Wilson IC 95%, alerta `n<30` operacional e aviso explícito que holdout interno != OWASP/Juliet. | `VALIDATED` |
| **AUD-07** | Comparabilidade & Quality Gate | Aceitação de booleanos soltos sem manifesto e `fudgeFactorApplied` legado `<20` linhas. | `ComparabilityManifest` obrigatório com digests SHA-256 verificáveis e remoção integral de supressão `<20` linhas em `QualityGateEngine` / `scoringEngine`. | `VALIDATED` |
| **AUD-08** | SCA & Multi-Lockfile | Ausência de proveniência estrita de licenças e lockfiles múltiplos. | Suporte a 7 formatos (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `Cargo.lock`, `package.json`), `NOASSERTION` quando não comprovada. | `VALIDATED` |
| **AUD-09** | CI/CD & GitHub Actions | Actions sem pinagem completa ou rodando em Node 20 legado / uploads frágeis. | Actions pinadas por SHA de 40 chars (`actions/checkout@3d3c42e...`, `actions/setup-node@949feb2...`, `actions/upload-artifact@cf430e0...` Node 24), `if: hashFiles(...) != ''` e `scripts/ci-summary.mjs`. | `IMPLEMENTED` / `TESTED` (local `--self-test` 7/7 PASS; run remoto `NOT_VALIDATED`) |
| **AUD-10** | CI Run `44141919950` (Linux + Windows + UI) | Falha Linux no texto legítimo em `PrivacyAndTermsModal.tsx`, falha Windows `@typescript/typescript-win32-x64` (TS 7), e fallback numérico na UI. | `verify-independent-positioning.mjs` (141 arquivos PASS), `typescript@5.9.3` (`npm run lint` PASS local), UI honesta (`NOT_MEASURED`), suíte SSR + 10 fluxos HTTP (`uiAndE2e.test.ts` PASS). | `PARTIALLY_VALIDATED` (execução Windows remota `NOT_VALIDATED` até novo push) |

---

## 3. Comandos Executados e Resultados Reais Neste Workspace

| Comando | Resultado Real | Evidência Principal |
|---|---|---|
| `npm run lint` | `EXIT 0` | 0 erros TypeScript (`tsc --noEmit` v5.9.3) |
| `npm test` | `102/102 PASS` | 10 arquivos de teste (inclui `uiAndE2e.test.ts`), `0` falhas (`30.82s`) |
| `npm run test:security` | `23/23 PASS` | Keystore fail-closed, Scrypt `N=32768`, TOTP, WebAuthn, SSRF, Path Traversal (`23.45s`) |
| `npm run test:golden` | `7/7 PASS` | Split 3 conjuntos (`DEVELOPMENT`/`REGRESSION`/`INTERNAL_HOLDOUT`) (`1.20s`) |
| `npm run test:desktop` | `7/7 PASS` | `WinHoodPaths`, preload/IPC, bootstrap sequencial + fallback de porta (`3.10s`) |
| `npm run test:coverage` | `111/111 PASS` | Gate `c8` + `v8-to-istanbul` aprovado (`88.47% L` núcleo, `>=98.08%` críticos) |
| `node scripts/verify-npm-audit.mjs` | `PASSED` | `GOVERNED_BUILD_TIME_EXCEPTIONS_ACTIVE` (`0` não aprovadas, `5/5` governadas) |
| `node scripts/verify-independent-positioning.mjs` | `PASSED` | 141 arquivos varridos, 5/5 self-tests, 0 violações |
| `node scripts/ci-summary.mjs --self-test` | `PASSED` | 7/7 cenários de propagação verificados |
| `npm run build && npm run build:desktop` | `EXIT 0` | `dist/index.html` + `dist-desktop/{server.mjs,electron-main.mjs,electron-preload.cjs,build-manifest.json}` |

---

## 4. Limitações Explicitamente Declaradas

- **Execução Remota GitHub Actions (`ubuntu-latest` e `windows-latest`):** `NOT_VALIDATED` neste container até envio do commit e execução real do workflow.
- **Compilação `ISCC.exe` e E2E do Instalador Windows (`scripts/windows/test-installer-e2e.ps1`):** `NOT_VALIDATED` no container Linux (`winhoodDesktop` + `build:desktop` validados localmente; instalação silenciosa `/VERYSILENT`, `%LOCALAPPDATA%`, DPAPI nativo real e Windows Hello WinRT real exigem Windows 10/11).
- **Verificação WCAG 2.2 AA Presencial em Navegador:** Inspeção estrutural via SSR automatizada (`TESTED`); contraste visual ao vivo, armadilha de foco Tab e leitura real em NVDA/Narrator permanecem `NOT_VALIDATED`.
