# Relatório de Testes de Regressão e Validação Automatizada (`REGRESSION_TEST_REPORT.md`)

**Data de Execução:** 2026-11-17  
**Runner:** Node.js Test Runner (`npx tsx --test`) + V8 SourceMap Coverage Gate (`scripts/run-coverage-gate.mjs`) + E2E Smoke (`scripts/verify-desktop-runtime.mjs`)

---

## 1. Resumo das Suítes Executadas

| Suíte de Teste | Comando | Total de Casos | Passaram | Falharam | Tempo Médio | Estado |
|---|---|---|---|---|---|---|
| **Suíte Principal, Segurança, Motores e Regressão** | `npm test` (`src/engine/analyzer.test.ts`) | 94 subtests | 94 | 0 | ~38s | **VALIDADO** |
| **Suíte Dedicada de Segurança & AppSec** | `npm run test:security` | 29 subtests | 29 | 0 | ~16s | **VALIDADO** |
| **Gate de Cobertura V8 + SourceMap (13 Domínios)** | `npm run test:coverage` | 13 domínios (81 arquivos) | 13 domínios | 0 | ~42s | **VALIDADO** |
| **Verificação de Runtime Desktop & Instalador** | `npm run build:desktop` | 24 checks de artefato/runtime | 24 | 0 | ~8s | **VALIDADO** |

---

## 2. Cobertura Funcional de Não-Regressão

1. **Autenticação & Controle de Acesso:**
   - Primeiro cadastro bootstrap administrativo (`ADMIN`), bloqueio de elevação de privilégio para segundo usuário, login com senha Scrypt (`N=16384` legado e `N=32768` atual com migração transparente), Quick PIN com bloqueio de PINs triviais e lockout progressivo, MFA TOTP com proteção anti-replay e WebAuthn/FIDO2 Windows Hello.
2. **Motores Analíticos & Scoring:**
   - Análise AST/Estrutural em 8 linguagens, Taint Analysis com sanitizadores contextuais, detecção de segredos com entropia e redação, geração de SBOM CycloneDX 1.5 / SPDX 2.3 multi-lockfile e correlação OSV/NVD/EPSS/CISA KEV.
3. **Criptografia, Proveniência & Comparabilidade:**
   - Envelope Encryption V2 (`WINHOOD-ENVELOPE-V2`), separação de chaves por finalidade via HKDF (RFC 5869), detecção de rollback monotônico, verificação de Trust Store Ed25519, comparabilidade bimodal (`SAME_ENGINE` e `CROSS_TOOL`) e Quality Gates com `REQUIRED`, `OPTIONAL` e `INFORMATIVE`.
4. **Filtros Avançados de UI (`SecurityAssessmentSuiteModule`):**
   - Filtragem combinada por gravidade (`Critical`, `High`, `Medium`, `Low`), status de remediação (`OPEN`, `IN_REMEDIATION`, `REMEDIATED`, `EXEMPTED_OR_ACCEPTED`) e estado de validação em 6 níveis sincronizada com `App.tsx`.
