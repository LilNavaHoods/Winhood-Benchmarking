# Limitações Técnicas e Fronteiras de Escopo do WinHood (`docs/LIMITATIONS.md`)

Em conformidade com o princípio de **Transparência Ativa** do WinHood Benchmarking, este documento declara explicitamente o que cada motor da plataforma analisa, até onde vai sua profundidade técnica e quais são seus limites conhecidos.

---

## 1. SAST e Análise de Fluxo de Dados (`Taint Analysis`)

### 1.1 Profundidade por Linguagem (`Interprocedural` vs. `Parcial`)
- **Fluxo Interprocedural Completo (AST + Resolução de Módulos Locais):**
  - **TypeScript / JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`):** Parsing completo via `@babel/parser` com rastreamento de fontes (`req.query`, `req.body`, `req.params`, `req.headers`, `process.argv`, `window.location`), propagação por atribuições e chamadas de funções exportadas entre arquivos do mesmo workspace, até sumidouros críticos (`SQLi`, `Command Injection`, `Code Injection`, `Path Traversal`, `SSRF CWE-918`, `XSS`, `Unsafe Deserialization`).
- **Fluxo Intraprocedural e Estrutural Parcial:**
  - **Python, Java, Go, C#, Rust e SQL:** Analisados por parsers estruturais e rastreamento intraprocedural dentro da mesma unidade de compilação/função. Fluxos que atravessam múltiplas classes ou pacotes externos nessas linguagens são reportados com confiança reduzida (`MEDIUM`).

### 1.2 Sanitizadores Reconhecidos
O `TaintAnalyzer` reconhece sanitizadores determinísticos por categoria de sumidouro:
- **Conversão Numérica Estrita:** `Number()`, `parseInt(..., 10)`, `BigInt()`.
- **Codificação e Escape Web:** `encodeURIComponent()`, `DOMPurify.sanitize()`, `escapeHtml()`, `validator.escape()`.
- **Normalização de Caminhos:** `path.basename()` combinado com verificação de prefixo `path.resolve().startsWith(allowedRoot)`.
- **Consultas Parametrizadas:** Placeholders posicionais (`$1`, `$2`, `?`) e prepared statements sem interpolação de strings.
- **Proteção contra SSRF:** Validação explícita por `SsrfGuard.validateUrl()` / allowlist de hosts e bloqueio de IPs privados/link-local.

### 1.3 Limites Conhecidos de SAST/Taint
- **Reflexão e Metaprogramação:** Chamadas invocadas via reflexão (`Reflect.apply`, `getattr`, `Method.invoke`), `eval()` indireto ou contêineres de injeção de dependência baseados em strings em tempo de execução não têm grafo de chamadas estático completo.
- **Código Gerado Dinamicamente e Binários Nativos:** Código montado em runtime, WebAssembly (`.wasm`) ou addons nativos C/C++ (`.node`, `.so`, `.dll`) ficam fora do escopo da AST.

---

## 2. Detecção de Segredos (`SecretsCatalog`)

- **Padrões Cobertos:** Chaves de nuvem (`AKIA...`), tokens de controle de versão (`ghp_...`, `github_pat_...`, `glpat-...`), tokens de mensageria (`xoxb-...`, `xoxp-...`), chaves financeiras (`sk_live_...`), chaves privadas criptográficas (`-----BEGIN ... PRIVATE KEY-----`), tokens JWT hardcoded e atribuições diretas a variáveis sensíveis (`password`, `secret`, `apiKey`, `masterKey`, `privateKey`).
- **Entropia de Shannon:**Calculada sobre literais candidatos (`H >= 4.2 bits/caractere` para strings alfanuméricas longas e `H >= 3.8` em contextos de configuração sensível), com redação imediata (`***REDACTED***`) antes da persistência ou exibição.
- **Validação Opcional:** Verificação offline determinística de estrutura, prefixo, comprimento e checksum léxico (sem nunca realizar chamadas externas com o segredo encontrado).
- **Taxa Estimada de Falsos Positivos por Categoria:**
  - **Prefixos Estruturados Canônicos (AWS, GitHub, Stripe, PEM):** `< 1.0%` de falsos positivos.
  - **Atribuições Semânticas + Alta Entropia Genérica:** `~5% a 12%` em bases que utilizam hashes de integridade inline ou chaves públicas de teste, mitigado por filtros automáticos para hashes SHA-256 hexadecimais puros, UUIDs v4, caminhos de arquivos e diretórios de teste (`*.test.*`, `fixtures/`).

---

## 3. Software Composition Analysis (`SCA`)

- **Fontes de Vulnerabilidades (CVE):** Base de advisories estruturada compatível com o esquema aberto **OSV / NVD**, enriquecida com pontuação **CVSS v3.1/v4.0**, probabilidade de exploração **EPSS (FIRST)** e catálogo **CISA Known Exploited Vulnerabilities (KEV)**.
- **Periodicidade de Atualização:** Suporta mesclagem incremental determinística (`ScaCorrelator.mergeIncrementalAdvisories`) a cada execução de pipeline ou atualização do pacote de regras.
- **Limites de Resolução Transitiva:**
  - Quando o projeto fornece `package-lock.json` (ou lockfile equivalente), o WinHood resolve dependências diretas e transitivas.
  - Quando apenas o manifesto de topo (`package.json`, `requirements.txt`, `go.mod`) está presente sem lockfile, a resolução limita-se às dependências diretas declaradas e o estado de cobertura transitiva é registrado explicitamente.

---

## 4. Software Bill of Materials (`SBOM`)

- **Formatos Suportados:** **OWASP CycloneDX 1.5** (`application/vnd.cyclonedx+json`) e **Linux Foundation SPDX 2.3** (`application/spdx+json`), ambos com assinatura criptográfica `HMAC-SHA256` e `Ed25519`.
- **O Que é Incluído:** Nome do componente, versão exata/resolvida, `purl` (*Package URL*), tipo de escopo (produção vs. desenvolvimento), licença SPDX identificada e hash SHA-256 determinístico do descritor do componente.
- **O Que é Excluído:** Pacotes do sistema operacional subjacente (ex.: `glibc`, pacotes `apt`/`apk` fora do `Dockerfile`), dependências baixadas dinamicamente via rede em runtime e submódulos Git privados não presentes na árvore de arquivos analisada.

---

## 5. Infraestrutura como Código (`IaC`)

- **Provedores e Recursos Cobertos:**
  - **Terraform (`.tf`, `.tfvars`):** Buckets públicos/sem criptografia, Security Groups abertos para `0.0.0.0/0` em portas administrativas, políticas IAM com wildcard `*:*`, instâncias de banco de dados públicas ou sem criptografia em repouso.
  - **Kubernetes (`.yaml`, `.yml`):** Containers privilegiados (`privileged: true`), execução como root (`runAsNonRoot: false`), escalonamento de privilégios (`allowPrivilegeEscalation: true`), montagem de `hostPath` e ausência de limites de CPU/memória.
  - **Dockerfile:** Execução sem diretiva `USER` não-root, imagens base com tag mutável `:latest`, exposição de segredos em instruções `ENV`/`ARG` e uso inseguro de `ADD` remoto.
  - **Workflows de CI (`.github/workflows/*.yml`):** Uso inseguro de `pull_request_target` com checkout de código não confiável, permissões `write-all` e interpolação direta de contexto em scripts shell.
- **Não Cobertos:** Módulos Terraform remotos não materializados localmente, charts Helm com templates Go não renderizados previamente (`helm template`) e scripts imperativos proprietários de provisionamento.

---

## 6. Motor de Comparabilidade (`Comparability Engine`)

- **Premissas do Motor:** Uma comparação A/B válida pressupõe que os softwares comparados pertençam à mesma categoria funcional, sejam avaliados exatamente pela mesma versão do motor (`engineVersion`) e do catálogo de regras (`ruleCatalogSha256`), e possuam cobertura de escopo elegível compatível.
- **O Que Invalida uma Comparação:**
  - Diferença de cobertura de escopo analisado superior a `30` pontos percentuais entre o Software A e o Software B;
  - Tentativa de comparar resultados gerados por versões distintas do catálogo de regras ou com pesos de categorias divergentes;
  - Estado `INCONCLUSIVE` ou `NOT_MEASURED` nas dimensões críticas de desempate. Quando invalidada, o WinHood bloqueia a declaração de vencedor (`winnerSoftwareId: null`).

---

## 7. Trilha Criptográfica de Evidências (`Signed Evidence Chain`)

- **O Que a Assinatura Garante:**
  - Garante matematicamente que, a partir do momento em que os arquivos foram ingeridos pelo WinHood, nenhum apontamento, métrica, versão de regra, hash de artefato ou decisão de Quality Gate foi suprimido, alterado ou forjado (`SHA-256` encadeado + assinatura `HMAC-SHA256` / `Ed25519`).
- **O Que a Assinatura NÃO Garante:**
  - **Não prova equivalência com o ambiente de produção:** A assinatura atesta o código-fonte e os artefatos submetidos à auditoria, mas não prova por si só que esse mesmo código é o que está em execução nos servidores de produção (o que requer atestação de build reprodutível / SLSA no pipeline de deploy).
  - **Não garante ausência total de vulnerabilidades zero-day ou falhas de lógica de negócio específica:** A aprovação em um Quality Gate significa conformidade com os critérios verificáveis do catálogo aplicado dentro do escopo analisado.
