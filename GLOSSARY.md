# Glossário Oficial do WinHood Benchmarking (`GLOSSARY.md`)

Este glossário define os conceitos arquiteturais, matemáticos e de governança próprios da plataforma **WinHood Benchmarking**. O WinHood opera como uma categoria independente de auditoria de software, benchmarking comparativo A/B e trilha criptográfica de evidências baseada exclusivamente em padrões abertos (**SARIF 2.1.0, CWE, OWASP Top 10, CVSS, CycloneDX 1.5, SPDX 2.3**).

---

## 1. Modo MQR (Modern Quality Regime) & Perfil de Qualidade Estrita

- **Modo MQR (Modern Quality Regime):** Regime de avaliação multidimensional próprio do WinHood que classifica cada apontamento simultaneamente sob três atributos fundamentais de engenharia — **Segurança (`SECURITY`)**, **Confiabilidade (`RELIABILITY`)** e **Manutenibilidade (`MAINTAINABILITY`)** — com severidade independente por atributo (`BLOCKER`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) e rastreabilidade nas 12 categorias técnicas do WinHood.
- **Perfil de Qualidade Estrita (`winhood-strict-mqr` / `winhood-zero-trust-v2`):** Perfil canônico de auditoria que exige zero vulnerabilidades críticas ou de alta severidade confirmadas por fluxo de dados (Taint Analysis), zero segredos expostos, cobertura mínima de escopo analisado e verificação criptográfica íntegra da trilha de evidências.

---

## 2. Motor de Veracidade (`Veracity Engine`)

- **Motor de Veracidade:** Subsistema do WinHood responsável por contrastar declarações documentais ou comerciais de um software (ex.: "Zero SQL Injection", "Criptografia autenticada em repouso", "Sem dependências vulneráveis") contra as evidências empíricas coletadas na árvore sintática abstrata (AST), análise de fluxo (Taint Analysis), SBOM e testes controlados.
- **Estados de Veracidade:**
  - `VERIFIED_TRUE`: A afirmação foi comprovada pelas evidências técnicas dentro do escopo analisado.
  - `REFUTED_BY_EVIDENCE`: A afirmação foi contradita por uma ou mais evidências reproduzíveis (ex.: caminho source-to-sink não sanitizado ou segredo detectado).
  - `PARTIALLY_VERIFIED`: Parte dos controles declarados foi confirmada, mas há lacunas ou exceções no escopo.
  - `INCONCLUSIVE`: O escopo ou os artefatos fornecidos são insuficientes para confirmar ou refutar a afirmação.

---

## 3. Comparabilidade (`Comparability Engine`)

- **Comparabilidade A/B:** Propriedade técnica que garante que dois softwares submetidos a benchmarking sejam avaliados sob condições equivalentes (mesma versão do catálogo de regras, limites equivalentes de recursos, escopo elegível compatível e normalização de pesos apenas entre dimensões efetivamente mensuradas).
- **Invalidação de Comparação:** Uma comparação é marcada como `INCOMPATIBLE_SCOPE` ou `INCONCLUSIVE` quando há disparidade severa de cobertura de escopo, ausência de código-fonte/artefatos equivalentes ou divergência de versão do catálogo de regras. O WinHood nunca declara vencedor quando a comparabilidade é inválida.

---

## 4. Confiança da Evidência (`Evidence Confidence`)

- **Confiança da Evidência (`HIGH` | `MEDIUM` | `LOW`):** Indicador independente da nota técnica que expressa o grau de completude, reprodutibilidade e verificação criptográfica das provas coletadas em uma execução:
  - `HIGH`: Cobertura de ingestão e parsing ≥ 85%, execução determinística concluída sem erros, manifesto assinado (`HMAC-SHA256` / `Ed25519`) verificado e escopo representativo.
  - `MEDIUM`: Cobertura de parsing entre 50% e 84%, ou presença de arquivos ignorados por limites operacionais documentados, mantendo assinatura válida.
  - `LOW`: Cobertura de parsing < 50%, falha parcial de adaptadores ou ausência de verificação de integridade dos artefatos.
- Consulte [`docs/CONFIDENCE_MODEL.md`](./docs/CONFIDENCE_MODEL.md) para a formulação matemática completa.

---

## 5. Estados de Quality Gate (`Quality Gate Decisions`)

O motor de Quality Gate (`src/gate/QualityGateEngine.ts`) produz decisões determinísticas e versionadas com códigos de saída canônicos para automação em CI/CD:

| Estado do Gate | Código de Saída CLI Canônico | Significado Operacional |
| :--- | :---: | :--- |
| `APPROVED` | `0` | Todas as condições obrigatórias e opcionais do gate foram integralmente satisfeitas. |
| `APPROVED_WITH_RESERVATIONS` | `1` (em modo estrito CI) / `0` (em modo padrão) | Condições críticas de bloqueio passaram, mas limites secundários de aviso (ex.: dívida técnica moderada) requerem atenção. |
| `BLOCKED` | `2` (canônico CI) / `1` (legado CLI) | Uma ou mais condições bloqueantes falharam (ex.: vulnerabilidade crítica confirmada, segredo exposto ou violação de licença restritiva). |
| `REJECTED` | `2` (canônico CI) / `1` (legado CLI) | Rejeição imediata por falha crítica de segurança ou violação de integridade da trilha de evidências. |
| `INCONCLUSIVE` | `3` (canônico CI) / `2` (legado CLI) | Cobertura de escopo insuficiente (`< 50%`) ou confiança da evidência abaixo do mínimo exigido para decisão automatizada. |

---

## 6. Trilha Criptográfica de Evidências (`Signed Evidence Chain`)

- **Cadeia SHA-256 Append-Only:** Sequência encadeada de blocos de evidência onde cada etapa da análise incorpora o hash do bloco anterior (`previousHash`), impedindo adulteração retroativa.
- **Manifesto Assinado (`SignedEvidenceManifest`):** Envelope criptográfico assinado via `HMAC-SHA256` e `Ed25519` que vincula a versão do motor (`engineVersion`), o hash SHA-256 do catálogo de regras (`ruleCatalogSha256`), os hashes de todos os artefatos analisados (`artifactHashes`) e o hash da decisão do Quality Gate (`gateHash`).
