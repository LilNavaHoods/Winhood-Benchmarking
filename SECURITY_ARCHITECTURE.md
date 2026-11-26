# Arquitetura de Segurança do WinHood Benchmarking

Este documento descreve a arquitetura de segurança efetivamente implementada e verificada no WinHood Benchmarking (v4.4.0).

---

## 1. Modelo de Acesso: Local-First Irrestrito + TOTP Opcional + Modo Remoto Fail-Closed

- **Modo Local-First Padrão (`LOCAL_DESKTOP` / `LOCAL_WEB`):**
  - O workspace abre diretamente sem exigir cadastro de usuário, login convencional, senhas, GitHub OAuth ou Windows Hello.
  - O serviço faz bind em loopback (`127.0.0.1` localmente; `127.0.0.1:${WINHOOD_PORT:-3000}:3000` no Docker Compose), bloqueando exposição acidental na rede local.
  - **TOTP 2FA Opcional (`OptionalTotpService`, RFC 6238):** O operador pode ativar/desativar bloqueio opcional do workspace local com segredo TOTP cifrado em repouso (AES-256-GCM), janela anti-replay e cookie `winhood_totp_unlock` (`HttpOnly; SameSite=Strict`) + CSRF `winhood_csrf` (`SameSite=Strict`).
- **Modo de Implantação Remota Explícita (`REMOTE_DEPLOYMENT`):**
  - Exige `WINHOOD_REMOTE_API_TOKEN` com no mínimo 32 caracteres (falha fechada na inicialização se ausente ou fraco).
  - Validação em tempo constante (`SHA-256` + `crypto.timingSafeEqual`), bloqueio anti força-bruta por IP (`RemoteAuthFailureTracker` com limite de memória e expiração) e log estruturado de auditoria sem vazamento de tokens.
  - `WINHOOD_TRUST_PROXY=false` por padrão (ignora `X-Forwarded-For` forjado até configuração explícita de hops ou IPs confiáveis).

---

## 2. Armazenamento Persistente 100% Criptografado & Workspaces Efêmeros Separados

- **Zero Texto Puro em Armazenamento Persistente (`src/storage/EncryptedArtifactStore.ts`):**
  - Todo código-fonte ingerido é persistido exclusivamente dentro de envelopes autenticados `vault_bundle.whenc` (**AES-256-GCM + ZLIB-DEFLATE**) acompanhados de `vault_manifest.json` (apenas hashes SHA-256 e metadados não secretos).
  - Nenhum arquivo de código-fonte em texto puro é gravado em `WINHOOD_DATA_DIR/isolated_artifacts`.
  - Na inicialização e sob demanda (`POST /api/storage/migrate-legacy-plaintext`), o servidor executa migração atômica, verificada por round-trip byte-a-byte e idempotente de eventuais diretórios legados em texto puro.
  - Auditoria contínua disponível via `GET /api/storage/plaintext-audit` e verificada por testes de regressão com segredo canário.
- **Workspaces Temporários Efêmeros (`src/execution/EphemeralWorkspaceManager.ts`):**
  - Quando uma ferramenta isolada precisa ler arquivos do sistema de arquivos, eles são materializados apenas por job em `WINHOOD_TEMP_WORKSPACE_DIR` (`tmpfs` em memória no Docker `/tmp/winhood-workspaces`, `0700`/`0600`), **estritamente fora de `WINHOOD_DATA_DIR`** (o gerenciador recusa inicialização se apontar para dentro do volume persistente).
  - Bloqueia path traversal, null bytes, symlinks e quotas de quantidade/tamanho; garante limpeza determinística em conclusão, erro, cancelamento ou encerramento do processo.
  - *Nota honesta de armazenamento:* em SSDs com wear-leveling, exclusão de arquivos não é vendida como sobrescrita física garantida; a proteção em repouso apoia-se em `tmpfs` (RAM) para execução efêmera + AES-256-GCM para persistência.

---

## 3. Gerenciamento de Chaves e Rotação (`KeyManagementService.ts`)

- Gerencia chaves separadas por domínio criptográfico: `EVIDENCE_HMAC`, `EVIDENCE_ED25519` e `TOKEN_VAULT_AES256` (`WINHOOD-ENVELOPE-V2`).
- Separação estrita entre cofre de chaves privadas e Trust Store público Ed25519 (`assertSecretDomainSeparation()`).
- Em `PRODUCTION_SECURE`, falha fechada caso falte KEK seguro (`WINHOOD_KEYSTORE_MASTER_SECRET` ≥ 32 bytes em container/Linux ou DPAPI/Keychain nativo no desktop).
- A rotação de `TOKEN_VAULT_AES256` (`POST /api/security/keys/rotate`) dispara automaticamente a re-criptografia atômica de todos os bundles em `isolated_artifacts` via `EncryptedArtifactStore.reencryptAllBundles()` preservando chaves históricas apenas para verificação.

---

## 4. Isolamento de Analisadores Externos (`winhood-scanner-worker` + `ScannerJobOrchestrator`)

- Analisadores externos (`Semgrep`, `CodeQL`, `Gitleaks`, `ESLint`, `Ruff`, `Bandit`, `Roslyn`, `SpotBugs`, `Checkstyle`, `OSV-Scanner`, `Syft`, `Grype`, `Trivy`) executam **exclusivamente** no container dedicado `winhood-scanner-worker` (`Dockerfile.scanner-worker`):
  - Usuário não-root (`UID/GID 1001`), `read_only: true`, `cap_drop: ["ALL"]`, `no-new-privileges:true`, limites de CPU/RAM/PIDs, `tmpfs` por job e rede Docker interna sem saída para internet (`internal: true`).
  - Zero acesso a `/var/run/docker.sock`, zero tags `:latest`, zero `shell: true` (`spawnSync` com lista fixa de binários allowlisted e ambiente sanitizado).
  - Comunicação autenticada via `WINHOOD_SCANNER_WORKER_TOKEN` (comparação em tempo constante).
  - **Fail-Closed:** Se o worker não estiver configurado ou acessível, o `ScannerJobOrchestrator` retorna estado explícito `BLOCKED` sem nunca recorrer a execução direta insegura no host.

---

## 5. Proteção Anti-SSRF, Upload Safe, Vite Host Hardening & Governança de Dependências

- **Anti-SSRF (`SsrfGuard.ts`):** Valida URLs de destino contra DNS rebinding (`pinnedLookup`), bloqueia loopback (`127.0.0.0/8`, `::1`), RFC1918 (`10/8`, `172.16/12`, `192.168/16`), link-local/metadata (`169.254.169.254`), IPv4-mapped IPv6 e desabilita redirects automáticos (`redirect: 'manual'`).
- **Upload & ZIP Bomb Guard (`server.ts`):** Bloqueia ZIP bombs (razão de compressão anômala, >2.000 entradas, >64MB descomprimidos), path traversal e symlinks; aplica rate limiting (`429 RATE_LIMITED`) e limites diferenciados de payload (2MB padrão / 50MB upload).
- **Vite Dev Server (`vite.config.ts`):** Removido wildcard amplo `.run.app`; `resolveViteAllowedHosts()` aceita exclusivamente hostnames explícitos (`localhost`, `127.0.0.1` e hosts válidos derivados de `NG_ALLOWED_HOSTS`/`WINHOOD_ALLOWED_HOSTS`/`APP_URL`), rejeitando `*` e sufixos com ponto inicial.
- **Governança de Vulnerabilidades NPM (`scripts/verify-npm-audit.mjs`):** Exige correspondência exata em `package + advisoryId + severity + version/affectedRange + dependencyPath`, rejeita exceções expiradas/duplicadas/ambíguas e nunca classifica exceções governadas como `ZERO_VULNERABILITIES`.

---

## 6. Trilha Criptográfica de Evidências (`evidenceProvenanceEngine.ts`)

- Cada execução gera cadeia `SHA-256` append-only + manifesto assinado (`HMAC-SHA256` + `Ed25519`) cobrindo resultados, hashes de artefatos, decisão do Quality Gate e `provenanceMetadata` (incluindo `cryptographicScopeDisclaimer`).
- Qualquer adulteração nos achados ou nos metadados de proveniência é detectada com estado `TAMPERED` e rebaixa o Quality Gate para `INCONCLUSIVE`.
