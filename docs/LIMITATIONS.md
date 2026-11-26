# Limitações Técnicas e Fronteiras de Escopo do WinHood (`docs/LIMITATIONS.md`)

Em conformidade com o princípio de **Transparência Ativa** do WinHood Benchmarking, este documento declara explicitamente o que cada motor da plataforma analisa, até onde vai sua profundidade técnica real e quais são seus limites verificáveis.

---

## 1. SAST e Análise de Fluxo de Dados (`TaintAnalyzer` + `ParserRegistry`)

### 1.1 Profundidade Real por Linguagem (Declarada em `ParserRegistry.getLanguageAnalyticalCapabilities()`)
- **`FULL_AST` + Call-Graph Multi-Hop Interprocedural (`@babel/parser`):**
  - **TypeScript / JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`):** Parsing sintático completo via `@babel/parser`, construção de grafo de chamadas (`TaintCallGraph`) com resolução sensível a `import`/`export` entre arquivos do workspace e rastreamento multi-hop configurável (`maxCallDepth` padrão `6`, limite de nós visitados `maxVisitedNodes = 500`, orçamento temporal `maxTimeMs = 2000ms`), detecção segura de ciclos/recursão (`CYCLE_DETECTED`) e registro explícito de truncamento (`MAX_DEPTH_REACHED`, `RESOURCE_BUDGET_EXCEEDED`).
- **`STRUCTURAL_AST` (Parser Estrutural Baseado em Tokens/Blocos):**
  - **Python, Java, Go, C#, Rust e SQL:** Analisados por parsers estruturais próprios (`winhood-*-token-ast-v1`) sem execução de compilador nativo (`javac`, `Roslyn/MSBuild`, `CPython`, `go/types`, `rustc`). Para análise semântica profunda de bytecode/tipos, utilize os analisadores externos no container dedicado `winhood-scanner-worker` (`Semgrep`, `Ruff`, `Bandit`, `SpotBugs`, `Roslyn`, `CodeQL`).

### 1.2 Sanitizadores Sensíveis a Contexto
O `TaintAnalyzer` modela sanitização **por categoria de sumidouro** (evitando falsos negativos causados por sanitizador incompatível):
- **SQL Injection (`CWE-89`):** Consultas parametrizadas (`$1`, `?`), `Number()`, `parseInt(..., 10)`, `BigInt()`. *Nota:* `encodeURIComponent()` ou `escapeHtml()` **não** neutralizam SQLi.
- **XSS (`CWE-79`):** `DOMPurify.sanitize()`, `escapeHtml()`, `validator.escape()`, `he.encode()`.
- **Path Traversal (`CWE-22`):** `path.basename()` combinado com verificação de prefixo canônico (`path.resolve().startsWith(allowedRoot)`).
- **SSRF (`CWE-918`):** `SsrfGuard.validateUrl()` / bloqueio de IPs privados, loopback e link-local.
- **Command Injection (`CWE-78`):** Substituição por `execFile`/`spawn` com `shell: false` e allowlist estrita de argumentos.

### 1.3 Limites Conhecidos de SAST/Taint
- **Despacho Dinâmico e Reflexão (`DYNAMIC_CALL_DISPATCH`):** Chamadas computadas (`handlers[action](input)`), `Reflect.apply`, `.call`/`.apply`/`.bind`, `getattr` ou injeção de dependência em runtime são registradas explicitamente em `incompletePaths` com impacto `INCONCLUSIVE` / confiança reduzida em vez de serem silenciadas.
- **Sem Type-Checker Cross-Package:** Tipos inferidos exclusivamente a partir de pacotes externos em `node_modules` ou binários nativos (`.wasm`, `.node`, `.dll`, `.so`) não são resolvidos pelo motor nativo.
- **Sem Execução Simbólica Path-Sensitive Completa:** Condições de ramificação complexas dependentes de estado de runtime podem gerar falsos positivos ou falsos negativos que devem ser validados com ferramentas complementares.

---

## 2. Detecção de Segredos (`SecretsCatalog`)

- **Padrões Cobertos:** Chaves de nuvem (`AKIA...`), tokens VCS (`ghp_...`, `github_pat_...`, `glpat-...`), mensageria (`xoxb-...`), chaves financeiras (`sk_live_...`), chaves privadas PEM, JWTs hardcoded e atribuições a variáveis sensíveis com análise de entropia de Shannon e redação imediata (`***REDACTED***`).
- **Validação Estritamente Offline:** Nunca realiza chamadas externas de rede utilizando segredos detectados.
- **Limitações:** Segredos ofuscados, fragmentados em múltiplas variáveis ou armazenados em binários compactados não são detectados por inspeção estática textual.

---

## 3. Software Composition Analysis (`SCA`) e Versionamento

- **Comparadores Sensíveis a Ecossistema (`ScaCorrelator.ts`):**
  - `compareSemver` (SemVer 2.0.0 completo: pré-releases `1.0.0-alpha.1 < 1.0.0`, ignora `+build`).
  - `comparePep440` (PyPI PEP 440: épocas, `.devN < aN < bN < rcN < final < .postN`).
  - `compareMavenVersion` (Maven: `-SNAPSHOT`, `alpha`/`beta`/`rc`/`final`).
  - `compareNugetVersion` (NuGet: 4 segmentos `major.minor.patch.revision` + pré-releases).
- **Honestidade de Frescor (`freshnessStatus`):**
  - `LIVE_FEED_FRESH` (≤24h sincronizado), `VALID_CACHE` (≤30 dias), `OFFLINE_LIMITED_BASELINE` (base embarcada curada), `STALE_DATA` (>30 dias), `SOURCE_UNAVAILABLE`.
  - **Limitação Crítica:** No modo `OFFLINE_LIMITED_BASELINE`, `isComprehensiveDatabase` é explicitamente `false` — a base embutida **não** substitui varredura SCA abrangente via `osv-scanner`/`grype`/`trivy` no `winhood-scanner-worker` ou sincronização ativa OSV/NVD/EPSS/KEV.

---

## 4. Software Bill of Materials (`SBOM`)

- **Formatos Suportados:** **OWASP CycloneDX 1.5 / 1.7** e **SPDX 2.3 / 3.0.1** com assinatura `HMAC-SHA256` + `Ed25519`.
- **Manifestos e Lockfiles Suportados:** `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`, `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.lockfile`, `*.csproj`, `packages.lock.json`.
- **Transparência de Incertezas:** Registra explicitamente `dependencyPath`, `versionResolutionState` (`RESOLVED_LOCKED`, `DECLARED_RANGE`, `UNRESOLVED`), `unresolvedDependenciesCount` e `unknownLicenseCount` (usando `NOASSERTION` quando a licença não é comprovável).
- **Exclusões:** Pacotes do SO base fora do escopo do projeto e dependências baixadas dinamicamente em runtime.

---

## 5. Analisadores Externos e Container Isolado (`winhood-scanner-worker`)

- Ferramentas externas (`Semgrep`, `CodeQL`, `Gitleaks`, `ESLint`, `Ruff`, `Bandit`, `Roslyn`, `SpotBugs`, `Checkstyle`, `OSV-Scanner`, `Syft`, `Grype`, `Trivy`) **nunca** são marcadas como `OPERATIONAL` apenas porque o binário existe no PATH: exigem execução real de auto-teste no worker isolado e validação estrutural da saída.
- Sem o serviço `winhood-scanner-worker` acessível, a execução falha fechada com estado `BLOCKED` (zero fallback silencioso para execução direta no host).

---

## 6. Validação Comparativa (`CrossToolBenchmarkHarness`) e Posicionamento Independente

- O WinHood disponibiliza corpus controlado interno (10 classes / 20 casos TP/TN em `src/validation/CrossToolBenchmarkHarness.ts`) com ingestão objetiva de SARIF 2.1.0 para comparação reproduzível contra SonarQube Cloud, Semgrep e CodeQL.
- **Restrição Metodológica Obrigatória:** Resultados sobre corpus controlado interno **não** constituem validação independente externa com repositórios de terceiros e **não** permitem declarar equivalência com SonarQube Cloud, Semgrep ou CodeQL sem execução real dessas ferramentas sobre o mesmo corpus. Ferramentas não executadas permanecem marcadas como `NOT_EXECUTED`.

---

## 7. Trilha Criptográfica de Evidências (`Signed Evidence Chain`)

- **O Que a Assinatura Garante (Tamper-Evidence):** Garante integridade verificável após a emissão do manifesto — qualquer adulteração nos achados, cadeia `SHA-256`, metadados de proveniência (`provenanceMetadata`), hashes de entrada/saída ou decisão de Quality Gate invalida a verificação (`TAMPERED`).
- **O Que a Assinatura NÃO Garante:** Não substitui atestação de build reprodutível/SLSA do ambiente de produção, não garante ausência de vulnerabilidades fora do escopo analisado e não prova segurança absoluta do host onde a chave local reside se o próprio sistema operacional estiver comprometido.
