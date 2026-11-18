# Relatório de Remediação de CI/CD Multiplataforma (`CI_REMEDIATION_REPORT.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base diagnosticado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` (GitHub Actions Run `44141919950`)
- **Ambiente local de verificação:** Container Linux (`linux x64`), `Node.js v22.23.2`, `npm 10.9.8`
- **Arquivos principais:** `.github/workflows/ci-multiplatform.yml`, `scripts/verify-independent-positioning.mjs`, `scripts/verify-npm-audit.mjs`, `scripts/ci-summary.mjs`, `package.json`, `package-lock.json`
- **Estado de validação:** `PARTIALLY_VALIDATED` *(todos os scripts, linters, testes e autotestes de CI foram executados e aprovados localmente no container Linux; a execução remota dos jobs `linux-validation`, `windows-desktop-validation` e `ci-summary` no GitHub Actions permanece `NOT_VALIDATED` até o próximo push)*

---

## 1. Diagnóstico Causa-Raiz da Run `44141919950` e Correções Aplicadas

| Problema na Run `44141919950` | Causa Raiz | Solução Implementada | Evidência Local | Estado |
|---|---|---|---|---|
| **1. Falha Linux na etapa de posicionamento independente** | Grep literal proibia qualquer ocorrência da string `SonarQube`, falhando no aviso legítimo de privacidade em `src/components/PrivacyAndTermsModal.tsx` (*"quando você mesmo configura sua chave/token e autoriza a ação"*). | Criado `scripts/verify-independent-positioning.mjs` com análise semântica contextualizada (bloqueia falsas alegações de parceria/certificação/propriedade e permite divulgações técnicas/privacidade legítimas) e 5 cenários de autoteste embutidos. | `node scripts/verify-independent-positioning.mjs` -> `PASSED (141 files, 5/5 self-tests, 0 violations)` | `VALIDATED` (local) |
| **2. Falha Windows em `npm run lint` (`@typescript/typescript-win32-x64`)** | `typescript@7.0.2` (preview nativo Go) dependia de pacote opcional binário específico de plataforma (`@typescript/typescript-win32-x64`) que falhava na resolução após `npm ci` no runner Windows. | Substituído por `typescript@5.9.3` (implementação oficial 100% JavaScript puro multiplataforma sem binários nativos por SO/arquitetura) sincronizado em `package.json` e `package-lock.json`. | `npm run lint` (`tsc --noEmit`) -> `EXIT 0` (`0` erros) | `PARTIALLY_VALIDATED` (`VALIDATED` em Linux; `NOT_VALIDATED` em `windows-latest` remoto) |
| **3. Upload de artefatos falhando quando etapa anterior falha** | `actions/upload-artifact` era invocado sem verificar a existência física dos relatórios em disco. | Adicionada condição `if: always() && hashFiles('coverage/coverage-summary.json') != ''` (Linux) e `if: always() && hashFiles('dist-desktop/build-manifest.json') != ''` (Windows) + `if-no-files-found: warn`. | Inspecionado em `.github/workflows/ci-multiplatform.yml:90,255` | `IMPLEMENTED` / `TESTED` |
| **4. Sumário de CI com `"PASSED"` fixo / mascaramento de falhas** | O resumo anterior não refletia estados reais de etapas puladas (`SKIPPED`), não executadas (`NOT_EXECUTED`) ou artefatos ausentes por falha do produtor. | Criado `scripts/ci-summary.mjs` mapeando `steps.<id>.outcome` e `needs.<job>.result` para `PASSED \| FAILED \| SKIPPED \| NOT_EXECUTED \| PARTIAL \| BLOCKED`, preservando falha global (`exit 1` em `FAILED`/`BLOCKED`). | `node scripts/ci-summary.mjs --self-test` -> `7/7 propagation scenarios verified` | `VALIDATED` (autoteste local) |
| **5. `npm ci` executando scripts arbitrários e Electron no Windows** | Uso de `npm ci` padrão sem `--ignore-scripts`. | Padronizado `npm ci --ignore-scripts` + `npm ls --depth=0` nos dois ambientes, com provisionamento explícito do binário Electron no Windows (`if (-not (Test-Path "node_modules\electron\dist\electron.exe")) { node node_modules/electron/install.js }`). | `.github/workflows/ci-multiplatform.yml:59,188-192` | `PARTIALLY_VALIDATED` |

---

## 2. Inventário de GitHub Actions, Pinagem SHA-256 (40 chars) e Runtime Node 24

| Action Utilizada | Arquivo de Workflow | Commit SHA Pinado (40 caracteres) | Tag Equivalente | Runtime Declarado |
|---|---|---|---|---|
| `actions/checkout` | `.github/workflows/ci-multiplatform.yml` (linhas 40, 172, 272) | `3d3c42e5aac5ba805825da76410c181273ba90b1` | `v7.0.1` | `node24` |
| `actions/setup-node` | `.github/workflows/ci-multiplatform.yml` (linhas 43, 175, 275) | `949feb2413d6458794dcd2491c4babbbce0c15c1` | `v6.4.0` | `node24` |
| `actions/upload-artifact` | `.github/workflows/ci-multiplatform.yml` (linhas 91, 256) | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` | `v7.0.1` | `node24` |
| `./integrations/github-action` | `integrations/github-action/action.yml` (local composite action) | Local (`uses: ./integrations/github-action`) | `v4.4.0` | `composite` (`bash` + Node 22) |

---

## 3. Validação dos 7 Cenários de Propagação do Sumário (`scripts/ci-summary.mjs --self-test`)

1. **Cenário 1 (`Linux success + Windows success`):** Todos os steps e artefatos presentes -> `overallStatus = PASSED`.
2. **Cenário 2 (`Linux success + Windows failure`):** Falha em `windows.steps.lint`, etapas subsequentes `SKIPPED` -> `overallStatus = FAILED`, `windowsJobStatus = FAILED`.
3. **Cenário 3 (`Linux failure + Windows skipped`):** Falha em `linux.steps.positioning` -> `overallStatus = FAILED`, `linuxSteps.lint = SKIPPED` (nunca `"PASSED"` fixo).
4. **Cenário 4 (`Falha antes da cobertura`):** `lint = FAILED`, `coverage = SKIPPED`, artefato de cobertura ausente -> `coverageArtifact.status = SKIPPED`, `overallStatus = FAILED`.
5. **Cenário 5 (`Artefato ausente após falha da etapa produtora`):** `coverage = FAILED` e `coverage-summary.json` ausente -> `coverageArtifact.status = FAILED` com explicação causal explícita.
6. **Cenário 6 (`Build desktop não executado`):** `build_desktop = NOT_EXECUTED` -> `desktopArtifact.status = NOT_EXECUTED`, `overallStatus = PARTIAL`.
7. **Cenário 7 (`Execução parcialmente concluída / bloqueada`):** Job Windows cancelado ou `inno_compile = BLOCKED` -> `overallStatus = BLOCKED`.
