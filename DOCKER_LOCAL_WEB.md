# WinHood Benchmarking — Modo Docker Local-Web & Scanner Worker Isolado

Execute a plataforma completa do **WinHood Benchmarking** (frontend React 19 + backend Express + cofre cifrado `WINHOOD-ENVELOPE-V2` + armazenamento persistente 100% criptografado + **container dedicado `winhood-scanner-worker`** + motores SAST/Taint/SCA/IaC/SBOM/Benchmarking + TOTP 2FA opcional) diretamente no navegador em **`http://localhost:3000`**, sem precisar de instalador `.exe`.

---

## 1. Requisitos

- **Docker Desktop** (Windows/macOS) ou **Docker Engine + Docker Compose v2** (Linux).
- Nenhuma conta externa, login obrigatório, OAuth ou senha inicial é exigida — o workspace abre diretamente em modo **Local-First irrestrito** (com TOTP 2FA opcional na barra superior).

---

## 2. Topologia de Containers e Isolamento (Zero `:latest`, Zero `docker.sock`)

O `docker-compose.yml` provisiona dois serviços principais (mais o serviço opcional `sonar-local` isolado no perfil `--profile sonar`):

1. **`winhood` (`Dockerfile`, base fixada `node:22.14.0-bookworm-slim`):**
   - Publicado exclusivamente em `127.0.0.1:${WINHOOD_PORT:-3000}:3000` (nunca exposto na LAN por padrão).
   - Usuário não-root `winhood` (`UID/GID 1001`), `cap_drop: ["ALL"]`, `security_opt: ["no-new-privileges:true"]`, `init: true`.
   - Volume persistente `/data/winhood` (`winhood_data`, `0700`) contendo **exclusivamente dados cifrados** (`vault_bundle.whenc` + `vault_manifest.json` não secreto; zero código-fonte em texto puro em disco).
   - Diretório efêmero `/tmp/winhood-workspaces` montado em **`tmpfs`** (`noexec,nosuid,nodev`) separado do volume persistente.
2. **`winhood-scanner-worker` (`Dockerfile.scanner-worker`, base fixada `node:22.14.0-bookworm-slim`):**
   - Container dedicado para execução isolada de analisadores externos com **versões explicitamente fixadas**: Ruff `0.9.6`, Bandit `1.8.3`, Semgrep `1.109.0`, Gitleaks `8.24.0`, OSV-Scanner `1.9.2`, Syft `1.20.0`, Grype `0.89.0`.
   - **Sem portas expostas no host**, conectado apenas à rede interna `winhood_scanner_internal` (`internal: true`, sem saída para internet).
   - **Filesystem raiz somente leitura (`read_only: true`)**, `cap_drop: ["ALL"]`, `no-new-privileges:true`, limites explícitos (`mem_limit: 1536m`, `cpus: "2.0"`, `pids_limit: 128`) e workspaces efêmeros por job em `tmpfs`.
   - Autenticação mútua interna obrigatória via Bearer token de alta entropia (`WINHOOD_SCANNER_WORKER_TOKEN`) comparado em tempo constante (`crypto.timingSafeEqual`).
   - **Sem montagem de `/var/run/docker.sock`** e **sem fallback silencioso para execução no host**: se o worker não estiver disponível, os jobs externos retornam estado explícito `BLOCKED`.

---

## 3. Início Rápido em 1 Clique

### Windows (PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\docker-up.ps1
```

### Linux / macOS (Bash)

```bash
./scripts/docker-up.sh
```

O script executa automaticamente:
1. Cria `.env.docker` (nunca versionado no Git) a partir de `.env.docker.example` gerando dois segredos CSPRNG de 32 bytes distintos: `WINHOOD_KEYSTORE_MASTER_SECRET` e `WINHOOD_SCANNER_WORKER_TOKEN` (permissão `0600` em Linux/macOS).
2. Executa `docker compose --env-file .env.docker up -d --build`.
3. Aguarda o healthcheck real (`GET /api/health`) ficar saudável.
4. Exibe o endereço pronto de acesso: `http://localhost:3000` (ou a porta configurada em `WINHOOD_PORT`).

> Para iniciar também a instância opcional do SonarQube Community local (`http://localhost:9000`), acrescente `--with-sonar` (Linux/macOS) ou `-WithSonar` (PowerShell).

---

## 4. Início Manual com Docker Compose

```bash
cp .env.docker.example .env.docker
# Edite .env.docker e defina segredos distintos (>= 32 bytes hex cada):
#   WINHOOD_KEYSTORE_MASTER_SECRET=$(openssl rand -hex 32)
#   WINHOOD_SCANNER_WORKER_TOKEN=$(openssl rand -hex 32)
docker compose --env-file .env.docker up -d --build
```

Com o perfil opcional do SonarQube local:

```bash
docker compose --env-file .env.docker --profile sonar up -d --build
```

---

## 5. Persistência Cifrada, Migração de Legado e Encerramento Gracioso

- **Armazenamento Persistente Sem Plaintext**: O `EncryptedArtifactStore` grava todo código ingerido exclusivamente em `vault_bundle.whenc` (AES-256-GCM + ZLIB) acompanhado de `vault_manifest.json` (hashes SHA-256 não secretos). Ao inicializar, o servidor executa automaticamente migração atômica, verificada por round-trip e idempotente de eventuais arquivos em texto puro legados (`GET /api/storage/plaintext-audit` permite auditar a qualquer momento).
- **Encerramento Multiplataforma**: O servidor intercepta `SIGTERM`/`SIGINT` (Linux/macOS/Docker) e mensagens IPC controladas (`WINHOOD_GRACEFUL_SHUTDOWN`, Windows), drena conexões keep-alive, cancela jobs pendentes, executa flush atômico do banco, remove workspaces efêmeros ativos e encerra com código de saída `0`.
- **Backup do volume persistente**:

```bash
docker run --rm -v winhood_data:/data:ro -v "$(pwd)":/backup alpine:3.21.3 \
  tar czf /backup/winhood-data-backup.tar.gz -C /data .
```

- **Diagnóstico e encerramento**:

```bash
docker compose ps
docker compose logs -f winhood winhood-scanner-worker
docker compose down
```

- **Validação E2E automatizada**:
  - Contra container em execução: `node scripts/verify-docker-local-web.mjs --base-url http://127.0.0.1:3000`
  - Standalone (sem daemon Docker): `node scripts/verify-docker-local-web.mjs --self-hosted`
