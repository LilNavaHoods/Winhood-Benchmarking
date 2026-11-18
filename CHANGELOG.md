# Changelog — WinHood Benchmarking (`CHANGELOG.md`)

Todas as mudanças notáveis da plataforma **WinHood Benchmarking** seguem **Versionamento Semântico (SemVer 2.0.0)** sem quebra dos contratos públicos existentes.

---

## [4.4.0] - 2026-11-18 — Remediação Pós-Auditoria CI (`44141919950`), Governança NPM, Cobertura `c8` + `v8-to-istanbul`, Keystore Fail-Closed e UI Honesta

### Desbloqueio Multiplataforma de CI/CD e Governança de Dependências (Fases 1, 2 & 8)
- **Resolução do erro Windows `@typescript/typescript-win32-x64`:** Padronização em `typescript@5.9.3` (JavaScript puro multiplataforma) e `npm ci --ignore-scripts` com `package-lock.json` v3 único (zero `bun.lock`).
- **Verificador Semântico de Posicionamento Independente (`scripts/verify-independent-positioning.mjs`):** Permite referências técnicas legítimas e avisos de consentimento do usuário (`PrivacyAndTermsModal.tsx`), bloqueando apenas alegações falsas de parceria comercial, certificação oficial ou propriedade de terceiros (5/5 cenários de autoteste verificados).
- **Governança de Vulnerabilidades NPM (`scripts/verify-npm-audit.mjs` & `security/npm-audit-exceptions.json`):** Eliminação permanente de 6 advisories na cadeia `electron-builder`/`node-gyp` e governança formal com prazo de validade (`2027-02-17`) e controles compensatórios para os 5 advisories build-time remanescentes de `picomatch <= 4.0.7` (`GHSA-fc5q-39xc-vjpf`).
- **Agregador Causal de CI (`scripts/ci-summary.mjs`) & Actions Node 24:** Pinagem por SHA de 40 caracteres (`actions/checkout@3d3c42e...`, `actions/setup-node@949feb2...`, `actions/upload-artifact@cf430e0...`), guarda `hashFiles(...) != ''` nos uploads e sumário multi-job validado em 7 cenários.

### Cobertura Convencional `c8` + `v8-to-istanbul` (`all: true`) (Fase 4)
- **Motor Oficial `c8@10.1.3` (`scripts/coverage-runner-core.mjs` & `scripts/run-coverage-gate.mjs`):** Conversão AST real V8 -> Istanbul com `all: true` e validação estrita de `SourceMap` derivada de uma única fonte (`OFFICIAL_13_COVERAGE_DOMAINS` em `src/execution/CoverageDomainInventory.ts`).
- **Calibração Matemática (`src/execution/coverageEngine.test.ts`):** Validada contra 11 microprojetos de referência (100%, 0% não importado, ~50% linhas, `if/else`, ternário, switch, curto-circuito `&&`/`||`/`??`, funções declaradas vs invocadas, tipos TS, SourceMap corrompido e múltiplos domínios).

### Keystore `PRODUCTION_SECURE` Fail-Closed, Quality Gate Unificado e Comparabilidade (Fases 3, 5, 6 & 10)
- **Keystore `WINHOOD-ENVELOPE-V2` Fail-Closed (`src/security/KeyManagementService.ts`):** Exige Windows DPAPI, macOS Keychain, Linux Secret Service ou `WINHOOD_KEYSTORE_MASTER_SECRET` em `PRODUCTION_SECURE`, bloqueando fallback para arquivo `.kek` local; separa `trust-store.json` de `keystore.json` e impede reutilização de `SONAR_SECRET_SALT`.
- **Quality Gate sem Fudge Factor (`src/gate/QualityGateEngine.ts` & `src/engine/scoringEngine.ts`):** Remoção da supressão de achados em changesets `< 20` linhas e unificação da lógica de decisão entre motor de score e Quality Gate (9 cenários validados).
- **Comparabilidade A/B com Manifesto Verificável (`src/comparability/index.ts`):** Rejeição de flags booleanas soltas sem `ComparabilityManifest` completo e hashes SHA-256 verificados.
- **Matriz Auth/TOTP/Scrypt (`src/security/security.test.ts`):** Validação E2E de QR Code PNG offline, persistência em restart, disable/reconfiguração TOTP, migração `N=16384 -> N=32768` e proteção contra downgrade.

### Split de 3 Conjuntos no Golden Dataset e Honestidade da UI (Fases 7, 11 & 12)
- **Golden Dataset em 3 Conjuntos (`DEVELOPMENT`, `REGRESSION`, `INTERNAL_HOLDOUT`):** Cobertura das 8 linguagens declaradas, IC 95% de Wilson, alerta operacional `n < 30` e declaração explícita de autoria interna.
- **UI Honesta & Suíte E2E de 10 Fluxos (`src/components/uiAndE2e.test.ts`):** Remoção de fallbacks numéricos fabricados em `DashboardModule.tsx`, `SonarDockerCloudHubModule.tsx`, `ToolsAndIntegrationsModule.tsx` e `HardwareAndDisplayBenchmarkModule.tsx` em favor de `NOT_MEASURED` / `N/A`, validada por auditoria DOM SSR e 10 fluxos HTTP reais.
