# Relatório de Testes de Regressão e Validação Automatizada (`REGRESSION_TEST_REPORT.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + suíte completa de 13 arquivos de teste
- **Ambiente:** Linux x64, `Node.js v22.23.2`, `npm 10.9.8`
- **Ferramentas:** `tsx --test` (`node:test`), `c8@10.1.3` + `v8-to-istanbul`, `react-dom/server` (`renderToStaticMarkup`)
- **Estado de validação:** `PARTIALLY_VALIDATED` *(todas as suítes automatizadas Linux passaram 100%; execução de testes em `windows-latest` e testes manuais WCAG em navegador real permanecem `NOT_VALIDATED`)*

---

## 1. Resumo das Suítes Executadas Neste Workspace

| Comando Executado | Arquivos / Escopo | Total de Testes | Passaram | Falharam | Duração Real | Estado |
|---|---|---|---|---|---|---|
| `npm run lint` | `tsc --noEmit` (`typescript@5.9.3`) | Todo o projeto | — | 0 erros | ~2.1s | `VALIDATED` |
| `npm test` | 10 arquivos de teste (inclui `uiAndE2e.test.ts`) | **102** (`96` top-level + `7` subtests desktop) | **102** | **0** | `30.82s` | `VALIDATED` |
| `npm run test:security` | `src/security/security.test.ts` | **23** | **23** | **0** | `23.45s` | `VALIDATED` |
| `npm run test:golden` | `src/intelligence/intelligence.test.ts` | **7** (inclui 11 cenários estatísticos Fase 7) | **7** | **0** | `1.20s` | `VALIDATED` |
| `npm run test:desktop` | `src/desktop/desktop.test.ts` | **7** | **7** | **0** | `3.10s` | `VALIDATED` |
| `npm run test:coverage` | 13 suítes sob `c8` + `v8-to-istanbul` (`all: true`) | **111** | **111** | **0** | `41.79s` | `VALIDATED` |
| `./node_modules/.bin/tsx --test src/execution/coverageEngine.test.ts` | Calibração matemática dos 11 microprojetos de referência | **2** (11 microprojetos) | **2** | **0** | `4.56s` | `VALIDATED` |
| `./node_modules/.bin/tsx --test packages/vscode-extension/test/extension.integration.test.ts` | Integração VS Code MVP + fallback offline | **2** | **2** | **0** | `3.77s` | `VALIDATED` |

---

## 2. Cobertura dos 10 Fluxos Críticos E2E (`src/components/uiAndE2e.test.ts`)

1. **Fluxo 1:** `/api/health` (`ONLINE`) + `/api/auth/bootstrap-status` + leitura do token real em disco + `/api/auth/bootstrap-admin` com emissão de cookies `winhood_session` (`HttpOnly`) e `winhood_csrf`.
2. **Fluxo 2:** Logout e novo login em `/api/auth/login` + validação de sessão em `/api/auth/me`.
3. **Fluxo 3:** Enrollment MFA TOTP (`/api/auth/mfa/setup`), extração do segredo Base32, confirmação RFC 6238 (`/api/auth/mfa/confirm`), re-login exigindo 2º fator (`mfaRequired: true`) e verificação `/api/auth/mfa/verify`.
4. **Fluxo 4:** Criação de projeto (`/api/projects`) e upload de 2 softwares com código-fonte real (`CleanApi` vs `VulnApi`) em `/api/softwares`.
5. **Fluxo 5:** Disparo de benchmark comparativo `AB_COMPARE` (`/api/benchmark-runs`) e polling até conclusão real (`COMPLETED` / `COMPLETED_WITH_WARNINGS`) com 2 `scoreCards`.
6. **Fluxo 6:** Consulta ao `/api/dashboard`, listagem de achados (`/api/findings`) e triagem DevSecOps (`/api/findings/:id/validate` -> `CONFIRMED`).
7. **Fluxo 7:** Validação de comparabilidade A/B (`validatePairComparability`) comprovando rejeição de `normalizedTaxonomyApplied: true` sem manifesto (`NOT_COMPARABLE`).
8. **Fluxo 8:** Avaliação de Quality Gate (`/api/quality-gates/evaluate`).
9. **Fluxo 9:** Exportação e verificação estrutural de relatórios SARIF 2.1.0, PDF 1.4 (`%PDF-1.4`), SBOM CycloneDX 1.5 (`/api/runs/:runId/sbom`) e verificação criptográfica da cadeia de evidências (`/api/evidence/:runId/verify` -> `valid: true`).
10. **Fluxo 10:** Consulta ao Keystore (`/api/security/keys/status`), desativação autenticada de MFA (`/api/auth/mfa/disable`), logout e bloqueio `401/403` de escrita pós-revogação.
