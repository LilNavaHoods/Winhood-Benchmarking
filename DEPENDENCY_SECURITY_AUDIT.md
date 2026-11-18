# Auditoria de Segurança de Dependências e Supply Chain (`DEPENDENCY_SECURITY_AUDIT.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + workspace remediado
- **Ambiente:** Linux x64, `Node.js v22.23.2`, `npm 10.9.8`
- **Ferramentas:** `npm audit --json`, `npm audit --omit=dev --json`, `npm ls --depth=0`, `scripts/verify-npm-audit.mjs`, `security/npm-audit-exceptions.json`
- **Estado de validação:** `VALIDATED` *(governança determinística local validada; validação em `windows-latest` via `npm ci --ignore-scripts` marcada `NOT_VALIDATED` até push remoto)*

---

## 1. Higiene de Lockfile e Resolução TypeScript

1. **Padronização NPM Exclusiva:** `package-lock.json` (lockfileVersion 3) sincronizado com `package.json`; ausência de `bun.lock` validada na raiz e no workflow CI.
2. **Resolução do Erro Windows `@typescript/typescript-win32-x64`:** Migração de TypeScript 7 preview nativo para `typescript@5.9.3` (100% JavaScript puro, multiplataforma sem pacotes binários opcionais por arquitetura). Validado localmente com `npm run lint` (`0` erros).
3. **Suporte Multi-Lockfile no Motor Analítico SCA:** Preservado em `src/analyzers/sca/SbomGenerator.ts` para projetos analisados (`package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `Cargo.lock`).

---

## 2. Resultado Real de Vulnerabilidades (`11 Inicial -> 5 Governadas`)

Dos **11 advisories iniciais de severidade alta** registrados na run `44141919950`:
- **6 advisories eliminados permanentemente** na cadeia `electron-builder` / `@electron/rebuild` / `node-gyp` / `app-builder-lib` / `dmg-builder` / `electron-builder-squirrel-windows` (via `electron@^45.3.3`, `electron-builder@^26.18.0` e `overrides` de `node-gyp@^11.1.0`, `glob@^14.0.6`, `esbuild@^0.28.2`, `minimatch@^11.0.9`).
- **5 advisories remanescentes (`high`, `0 critical`, `0 moderate`)** identificados por `npm audit --json` e `npm audit --omit=dev --json`, **todos oriundos de um único advisory upstream (`GHSA-fc5q-39xc-vjpf` em `picomatch <= 4.0.7`)**:
  1. `picomatch@4.0.7` (`vite@8.3.8 > picomatch@4.0.7`) — `dist-tag latest = 4.0.7` no registro npm; não existe versão corrigida publicada até 2026-11-17.
  2. `fdir@6.5.0` (transitivo de `vite > tinyglobby > fdir > picomatch`)
  3. `tinyglobby@0.2.17` (transitivo de `vite > tinyglobby > picomatch`)
  4. `vite@8.3.8` (mantido porque o downgrade sugerido para Vite `<= 6.4.3` reintroduziria 12 vulnerabilidades reais de Path Traversal e leitura WebSocket)
  5. `@vitejs/plugin-react@6.3.0` (associação transitiva com `vite@8.3.8`)

> **Transparência sobre `--omit=dev`:** Como `vite` e `@vitejs/plugin-react` figuram em `dependencies` no `package.json` para suportar o middleware de desenvolvimento do preview (`server.ts`), os 5 alertas também aparecem em `npm audit --omit=dev`. Contudo, no bundle de produção compilado (`dist/` + `dist-desktop/server.mjs`), o servidor Express serve ativos estáticos compilados e **nenhuma entrada fornecida por usuário ou projeto analisado é enviada ao `picomatch`**.

---

## 3. Evidência do Gate Determinístico (`verify-npm-audit.mjs`)

- **Comando executado:** `node scripts/verify-npm-audit.mjs`
- **Resultado real:**
  `[WinHood NPM Audit Governance] PASSED — Status: GOVERNED_BUILD_TIME_EXCEPTIONS_ACTIVE (Unapproved: 0, Governed Build-Time Exceptions: 5/5)`
- **Autoteste interno do gate:** 3 cenários (`GOVERNED_BUILD_TIME_EXCEPTIONS_ACTIVE` aceito, exceção expirada bloqueada, vulnerabilidade não registrada em `lodash` bloqueada).
- **Expiração obrigatória:** Todas as 5 exceções registradas em `security/npm-audit-exceptions.json` expiram em `2027-02-17T22:50:00Z` (falha fechada automática após esta data) e possuem condição explícita de remoção assim que `picomatch >= 4.0.8` for publicado.
