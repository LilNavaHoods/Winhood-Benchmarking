# Auditoria de Segurança de Dependências e Supply Chain (`DEPENDENCY_SECURITY_AUDIT.md`)

**Data de Verificação:** 2026-11-17  
**Gerenciador Oficial do Repositório:** NPM (`package-lock.json` lockfileVersion 3)

---

## 1. Higiene de Lockfile e Reprodutibilidade

1. **Padronização do Repositório WinHood:**
   - O arquivo `bun.lock` residual na raiz do repositório foi removido para eliminar divergências de resolução de árvore transitiva entre gerenciadores.
   - O arquivo `package-lock.json` encontra-se 100% sincronizado com `package.json`, validado via `npm ls --all` sem dependências órfãs ou conflitos de peer dependencies.
2. **Suporte Analítico a Projetos Externos Preservado:**
   - Embora o repositório WinHood utilize exclusivamente `package-lock.json`, o motor SCA/SBOM (`src/analyzers/sca/SbomGenerator.ts`) suporta integralmente a auditoria de projetos externos que utilizem `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` e `Cargo.lock`.

---

## 2. Advisories Remediados

| Pacote | Versão Anterior | Versão Atualizada | Severidade Original | Justificativa Técnica e Mitigação |
|---|---|---|---|---|
| `electron` | `^35.7.5` | `^45.3.3` | Moderate / High | Atualização para release corrigida contra advisories de Chromium/IPC, mantendo `contextIsolation: true`, `nodeIntegration: false` e `sandbox: true`. |
| `electron-builder` | `^26.0.12` | `^26.18.0` | Moderate | Atualização da cadeia de empacotamento Windows/Linux e dependências transitivas de arquivo/tar. |
| `esbuild` (override) | `<0.25.0` (transitivo) | `^0.28.2` | Moderate (GHSA-67mh-4wv8-2f99) | Override explícito em `package.json` garantindo que servidores de desenvolvimento transitivos incluam validação de origem. |
| `minimatch` (override) | `<10.2.1` (transitivo) | `^11.0.9` | High (ReDoS) | Override explícito eliminando vulnerabilidade de expressão regular exponencial em globs transitivos. |

---

## 3. Evidência de Verificação (`npm audit` e `npm ls`)

- **Comando executado:** `npm audit`
- **Resultado:** `found 0 vulnerabilities` (0 Critical, 0 High, 0 Moderate, 0 Low).
- **Comando executado:** `npm ls --depth=0`
- **Resultado:** Código de saída `0`, todas as dependências diretas e de desenvolvimento íntegras e resolvidas.
