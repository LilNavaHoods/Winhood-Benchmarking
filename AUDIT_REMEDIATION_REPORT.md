# Relatório de Auditoria Técnica e Remediação — WinHood Benchmarking v4.4.0

**Data da Auditoria:** 2026-11-17  
**Versão Auditada:** `4.4.0`  
**Escopo:** Arquitetura Full-Stack (React 19 + Express + TypeScript), Motores SAST/SCA/Taint/Scoring/Comparabilidade, Criptografia de Cofre (Keystore Envelope V2), Cobertura V8 Real e Empacotamento Desktop Windows (Electron + Inno Setup).

---

## 1. Sumário Executivo

O WinHood Benchmarking passou por uma auditoria multidisciplinar (AppSec, SAST/SCA, Engenharia de Qualidade, Criptografia, DevSecOps e Empacotamento Desktop) dividida em **9 fases controladas**. Todas as alterações preservaram integralmente as funcionalidades existentes e a suíte de regressão automatizada, eliminando estimativas heurísticas, metadados sintéticos de adaptadores não executados e fragilidades criptográficas de derivação de chaves.

---

## 2. Matriz de Achados Identificados, Causas Raiz e Remediações

| ID | Severidade | Domínio | Achado Técnico e Causa Raiz | Solução Implementada | Estado |
|---|---|---|---|---|---|
| **AUD-01** | Alta | Dependências & Supply Chain | Dessincronização entre `package.json`, `package-lock.json` e `bun.lock`; advisories transitivos em `electron`, `electron-builder`, `esbuild` e `minimatch`. | Padronização exclusiva em NPM (`package-lock.json` v3), remoção de `bun.lock` do repositório raiz, atualização de `electron@^45.3.3` e `electron-builder@^26.18.0`, e `overrides` auditáveis (`esbuild@^0.28.2`, `minimatch@^11.0.9`). `npm audit` = **0 vulnerabilidades**. | **CORRIGIDO / VALIDADO** |
| **AUD-02** | Crítica | Cobertura de Testes | `scripts/run-coverage-gate.mjs` estimava cobertura de linhas dividindo offsets de bytes V8 por uma constante heurística de 48 bytes por linha (`Math.ceil(maxEndOffset / 48)`). | Substituição integral por projeção convencional V8 + `node:module` `SourceMap` sobre os arquivos-fonte TypeScript/TSX reais, calculando separadamente `statements`, `lines`, `functions` e `branches` nos **13 domínios oficiais** (`src/execution/CoverageDomainInventory.ts`). | **CORRIGIDO / VALIDADO** |
| **AUD-03** | Alta | Rastreabilidade de Ferramentas | `buildToolAdaptersCatalog()` preenchia `lastExecutionAt` com timestamp atual e `lastExitCode = 0` por padrão antes da execução real do binário. | Separação estrita entre `integrationType` (`NATIVE`, `LOCAL_CLI`, `REMOTE_API`), estados de prontidão (`NATIVE_AVAILABLE`, `EXTERNAL_BINARY_DETECTED`, `NOT_INSTALLED`, `NOT_CONFIGURED`) e `resultCompleteness` (`COMPLETE`, `PARTIAL`, `EMPTY`, `INCONCLUSIVE`, `NOT_EXECUTED`). `lastExecutionAt` e `lastExitCode` permanecem `null` até execução real. | **CORRIGIDO / VALIDADO** |
| **AUD-04** | Crítica | Criptografia do Keystore | Uso anterior de segredo derivado de características previsíveis da máquina (`hostname`/`username`/`platform`) combinado com HMAC redundante sobre AES-GCM. | Reformulação para **Criptografia por Envelope (`WINHOOD-ENVELOPE-V2`)** em `src/security/KeyManagementService.ts`: DEK aleatória CSPRNG de 256 bits cifrada com AES-256-GCM (nonce único de 96 bits + AAD contextual), protegida por KEK (Windows DPAPI, segredo externo ou KEK local persistida com `0600`), derivação por finalidade via **HKDF-SHA256 (RFC 5869)**, contador monotônico anti-rollback (`.seq`) e **Trust Store Ed25519** verificável. | **CORRIGIDO / VALIDADO** |
| **AUD-05** | Média | Autenticação & KDF | `AuthService.ts` utilizava parâmetros Scrypt fixos (`N=16384`) sem metadados de custo para migração futura. | Evolução para formato parametrizado `scrypt:N=32768,r=8,p=1:<salt>:<hash>` com verificação retrocompatível de contas `N=16384` e migração transparente (`needsPasswordRehash`) no próximo login válido. | **CORRIGIDO / VALIDADO** |
| **AUD-06** | Alta | Profundidade Analítica & Validação | Ausência de distinção explícita entre profundidade AST (`FULL_AST` vs `STRUCTURAL_AST` vs `PARTIAL_RECOVERY`) e uso de um único corpus interno sem intervalos de confiança estatísticos. | Declaração explícita de `analyticalDepth` em `ParserRegistry.ts` (rebaixando confiança `HIGH` para `MEDIUM` em `PARTIAL_RECOVERY`), criação do `INDEPENDENT_VALIDATION_CORPUS` separado do corpus de regressão e cálculo de Intervalos de Confiança de 95% (Wilson Score), TPR/TNR/FPR/FNR e médias Macro/Micro em `GoldenDatasetRunner.ts`. | **CORRIGIDO / VALIDADO** |
| **AUD-07** | Alta | Comparabilidade A/B & Quality Gates | Comparabilidade tratava apenas execuções de mesmo motor e Quality Gates não distinguiam condições obrigatórias de opcionais/informativas diante de métricas `NOT_MEASURED`. | Comparabilidade bimodal (`SAME_ENGINE` vs `CROSS_TOOL`) classificada em `STRICTLY_COMPARABLE`, `QUALIFIED_COMPARISON` e `NOT_COMPARABLE` (bloqueando vencedor em `NOT_COMPARABLE`). Quality Gates com `requirementTier` (`REQUIRED`, `OPTIONAL`, `INFORMATIVE`). | **CORRIGIDO / VALIDADO** |
| **AUD-08** | Média | SCA, Multi-Lockfile & Licenças | `SbomGenerator.ts` dependia primariamente de `package-lock.json` para dependências transitivas JS/TS e aplicava catálogo estático de licenças sem diferenciar proveniência. | Suporte a projetos externos com `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` e `Cargo.lock`; proveniência estrita de licenças (`NOASSERTION` quando não comprovada); metadados de frescor (`advisoryFeedMetadata`) e validação estrutural CycloneDX 1.5 / SPDX 2.3. | **CORRIGIDO / VALIDADO** |
| **AUD-09** | Média | CI/CD & Supply Chain | GitHub Actions referenciadas por tags mutáveis (`@v4`, `@v7`) em `.github/workflows/ci-multiplatform.yml`. | Pinagem de todas as GitHub Actions por commit SHA completo de 40 caracteres, permissões `contents: read` e inclusão obrigatória de `npm run test:security` e `npm audit --audit-level=moderate`. | **CORRIGIDO / VALIDADO** |

---

## 3. Riscos Residuais e Limitações de Ambiente Declaradas

1. **Validação em Host Físico Windows (`PARCIALMENTE VALIDADO` neste container Linux):**
   - Os artefatos Desktop (`dist-desktop/electron-main.mjs`, `dist-desktop/electron-preload.cjs`, `dist-desktop/server.mjs`), o script de manifesto `installer/WinHoodBenchmarking.iss` e os fluxos de chamada PowerShell/WinRT (`Windows.Security.Credentials.UI.UserConsentVerifier` e `ProtectedData::Protect` DPAPI) foram validados estaticamente e por testes automatizados multiplataforma, mas a execução interativa do instalador `.exe` compilado pelo Inno Setup e do prompt biométrico nativo Windows Hello requer um host ou VM Windows 10/11 real (executado no job `build-and-verify-windows` do GitHub Actions).
2. **Escopo de Parsers Multi-Linguagem:**
   - JavaScript, TypeScript, JSX e TSX contam com AST completa (`FULL_AST`) via TypeScript Compiler API. Python, Java, Go, Rust, C# e SQL operam com análise estrutural de blocos, escopos e declarações (`STRUCTURAL_AST`), explicitamente sinalizada em cada achado e relatório técnico.
