# Plano de Execução de 12 Fases — Estado Consolidado (`IMPLEMENTATION_PHASES.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` (+ remediações finais neste workspace)
- **Ambiente:** Linux x64, `Node.js v22.23.2`, `npm 10.9.8`
- **Estado Global:** `PARTIALLY_VALIDATED` *(Fases locais executadas e testadas no container Linux; execução remota em GitHub Actions `ubuntu-latest`/`windows-latest` e validação presencial WCAG/Windows permanecem `NOT_VALIDATED`)*

---

## Matriz das 12 Fases do Plano de Remediação

| Fase | Prioridade | Escopo Técnico | Evidência Verificada Localmente | Estado Oficial |
|---|---|---|---|---|
| **Fase 1** | `P0` | Diagnóstico TypeScript (`typescript@5.9.3` JS puro), correção do posicionamento semântico (`verify-independent-positioning.mjs`) e correção de upload de artefatos na CI. | `npm run lint` (`0` erros), `verify-independent-positioning.mjs` (141 arquivos, 5/5 self-tests PASS). | `PARTIALLY_VALIDATED` *(remoto Windows `NOT_VALIDATED`)* |
| **Fase 2** | `P0` | Auditoria e governança NPM (`11 -> 5` advisories build-time `picomatch`, 0 não aprovadas) via `security/npm-audit-exceptions.json` e `verify-npm-audit.mjs`. | `node scripts/verify-npm-audit.mjs` PASS (`GOVERNED_BUILD_TIME_EXCEPTIONS_ACTIVE`, 3/3 self-tests). | `VALIDATED` |
| **Fase 3** | `P0` | Remoção de `fudgeFactorApplied` `<20` linhas em `QualityGateEngine`/`scoringEngine` e alinhamento de `ComparabilityManifest` + `Keystore` `PRODUCTION_SECURE` fail-closed. | 9 cenários Gate/Scoring PASS (`gateAndCompliance.test.ts`); `test:security` 23/23 PASS. | `VALIDATED` |
| **Fase 4** | `P0` | Motor convencional de cobertura `c8` + `v8-to-istanbul` (`all: true`), calibração em 11 microprojetos de referência e fonte única de 13 domínios. | `npm run test:coverage` PASS (`88.47% L` núcleo, `>=98.08%` críticos, 11/11 microprojetos PASS). | `VALIDATED` |
| **Fase 5** | `P1` | Segregação estrita de segredos (`WINHOOD_KEYSTORE_MASTER_SECRET`, proibição de `SONAR_SECRET_SALT`), Trust Store Ed25519 separado (`trust-store.json`) e limites documentados de rollback local. | `KeyManagementService` testado em `security.test.ts` (teste #22 PASS). | `PARTIALLY_VALIDATED` *(DPAPI/Keychain nativos exigem hosts Windows/macOS)* |
| **Fase 6** | `P1` | Comparabilidade A/B verificável com manifesto completo SHA-256 (`validatePairComparability`), rejeitando booleanos soltos sem prova. | `src/comparability/` com `100% L / 100% F / 98.08% B`; teste `Flow 7` e `gateAndCompliance.test.ts` PASS. | `VALIDATED` |
| **Fase 7** | `P1` | Golden Dataset em 3 conjuntos (`DEVELOPMENT`, `REGRESSION`, `INTERNAL_HOLDOUT`) across 8 linguagens, IC 95% Wilson, alerta `n<30` operacional e aviso de não-independência externa. | `npm run test:golden` 7/7 PASS (11 cenários estatísticos/integridade). | `VALIDATED` |
| **Fase 8** | `P1` | Hardening CI/CD multiplataforma (Actions Node 24 pinadas por SHA de 40 chars, `ci-summary.mjs` sem `"PASSED"` fixo, `npm ci --ignore-scripts`). | `node scripts/ci-summary.mjs --self-test` 7/7 cenários PASS. | `PARTIALLY_VALIDATED` *(run remoto `NOT_VALIDATED`)* |
| **Fase 9** | `P1` | Empacotamento Desktop Windows (`build:desktop`, SHA-256 manifest, `.iss`, script `test-installer-e2e.ps1` de 13 passos). | `npm run build:desktop` + `npm run test:desktop` 7/7 PASS no Linux. | `PARTIALLY_VALIDATED` *(compilação `ISCC.exe` e E2E `.exe` no Windows `NOT_VALIDATED`)* |
| **Fase 10** | `P2` | Matriz de Autenticação/TOTP/QR PNG/Scrypt `N=16384->32768`/anti-downgrade/preservação em falha de escrita. | `security.test.ts` subtestes #19–#23 PASS. | `VALIDATED` *(Windows Hello nativo WinRT em VM Windows `NOT_VALIDATED`)* |
| **Fase 11** | `P2` | Honestidade da UI (`NOT_MEASURED` em vez de fallbacks falsos) e suíte E2E SSR + 10 fluxos HTTP reais (`src/components/uiAndE2e.test.ts`). | `uiAndE2e.test.ts` 2/2 subtestes PASS (`npm test` 102/102 PASS). | `PARTIALLY_VALIDATED` *(inspeção visual ao vivo/contraste/leitor de tela WCAG `NOT_VALIDATED`)* |
| **Fase 12** | `P0`/`P2` | Sincronização de todos os 11 documentos existentes + `CHANGELOG.md` e emissão dos 9 novos relatórios exigidos sob os 7 estados epistemológicos oficiais. | Todos os 21 documentos atualizados/emitidos com comandos reais e limitações explícitas. | `VALIDATED` *(documentação sincronizada ao estado real)* |
