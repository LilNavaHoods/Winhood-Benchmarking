# WinHood Benchmarking — Guia Técnico Docker Local-Web & Scanner Worker Isolado

Execute a plataforma completa do **WinHood Benchmarking v4.4.0** (frontend React 19 + backend Express + cofre cifrado `AES-256-GCM` + armazenamento persistente auditável + **container dedicado `winhood-scanner-worker`** + motores nativos SAST/Taint/SCA/IaC/SBOM/Benchmarking + TOTP 2FA opcional) diretamente no navegador em **`http://localhost:3000`**.

---

## 1. Requisitos

- **Docker Desktop** (Windows/macOS) ou **Docker Engine + Docker Compose v2** (Linux).
- Nenhuma conta externa, login obrigatório, OAuth ou senha inicial é exigida — o workspace abre diretamente em modo **Local-First irrestrito** (com TOTP 2FA opcional na barra superior).

---

## 2. Topologia de Containers e Isolamento (Zero tags mutáveis, Zero `docker.sock`)

O `docker-compose.yml` provisiona dois serviços principais (mais o serviço opcional `sonar-local` no perfil `--profile sonar`):

1. **`winhood` (`Dockerfile`, base fixada `node:22.14.0-bookworm-slim`):**
   - Publicado exclusivamente em `127.0.0.1:${WINHOOD_PORT:-3000}:3000` (loopback local).
   - Usuário não-root `winhood` (`UID/GID 1001`), `cap_drop: ["ALL"]`, `security_opt: ["no-new-privileges:true"]`, `init: true`, `stop_grace_period: 20s`.
   - Volume persistente `/data/winhood` (`winhood_data`, `0700`) com artefatos cifrados (`vault_bundle.whenc`, `scanner_jobs_payloads.whenc`) e metadados não confidenciais auditáveis em `GET /api/storage/plaintext-audit`.
   - Diretório efêmero `/tmp/winhood-workspaces` montado em **`tmpfs`** (`noexec,nosuid`).
2. **`winhood-scanner-worker` (`Dockerfile.scanner-worker`, base fixada `node:22.14.0-bookworm-slim`):**
   - Estágio dedicado `worker-deps` para `node_modules` de produção (`express`) + autoteste em build (`import('express')` e checagem de binários).
   - Ferramentas com **versões explicitamente fixadas**: Ruff `0.9.6`, Bandit `1.8.3`, Semgrep `1.109.0` (em `/opt/winhood-pytools/bin` + regras offline em `/opt/winhood-scanner-rules/winhood-core.yaml`), Gitleaks `8.24.0`, OSV-Scanner `1.9.2`, Syft `1.20.0`, Grype `0.89.0` (em `/usr/local/bin`).
   - **Sem portas expostas no host**, conectado apenas à rede interna `winhood_scanner_internal` (`internal: true`, sem internet).
   - **Filesystem raiz somente leitura (`read_only: true`)**, `cap_drop: ["ALL"]`, `no-new-privileges:true`, limites explícitos (`mem_limit: 1536m`, `cpus: "2.0"`, `pids_limit: 128`), workspaces efêmeros em `tmpfs` e volume `winhood_scanner_cache:/data/scanner-cache` para bases offline do Grype e OSV-Scanner.
   - Autenticação mútua interna obrigatória via Bearer token (`WINHOOD_SCANNER_WORKER_TOKEN`, comparado com `crypto.timingSafeEqual`).
   - Execução assíncrona com grupos de processos destacáveis e cancelamento real via `POST /worker/jobs/:jobId/cancel` (`SIGTERM` → `SIGKILL` + limpeza do workspace).
   - **Sem montagem de `/var/run/docker.sock`** e **sem fallback silencioso no host**: se o worker estiver indisponível, jobs retornam `BLOCKED`.

---

## 3. Comandos Oficiais de Ciclo de Vida

### Iniciar (primeiro build ou atualização)

- **Windows (PowerShell):** `powershell -ExecutionPolicy Bypass -File .\scripts\docker-up.ps1`
- **Linux / macOS (Bash):** `./scripts/docker-up.sh`

Opções:
- `--no-build` / `-NoBuild`: sobe rapidamente sem reconstruir imagens.
- `--with-sonar` / `-WithSonar`: inicia também o SonarQube Community local (`http://localhost:9000`).

### Atualizar base offline do Grype (opcional)

Como o `winhood-scanner-worker` não possui acesso à internet, utilize o script de atualização sob demanda para popular o volume `winhood_scanner_cache` via container efêmero:

- **Linux / macOS:** `./scripts/docker-update-scanner-dbs.sh`
- **Windows (PowerShell):** `powershell -ExecutionPolicy Bypass -File .\scripts\docker-update-scanner-dbs.ps1`

Enquanto o cache offline do Grype ou OSV-Scanner estiver vazio, os respectivos scanners reportam explicitamente **`DATABASE_UNAVAILABLE`** (nunca "0 vulnerabilidades").

### Encerrar (preservando dados por padrão)

- **Linux / macOS:** `./scripts/docker-down.sh`
- **Windows (PowerShell):** `powershell -ExecutionPolicy Bypass -File .\scripts\docker-down.ps1`

### Remoção destrutiva de volumes (apaga projetos, keystore e cache)

- **Linux / macOS:** `./scripts/docker-down.sh --purge-volumes --confirm-data-loss`
- **Windows (PowerShell):** `powershell -ExecutionPolicy Bypass -File .\scripts\docker-down.ps1 -PurgeVolumes -ConfirmDataLoss`

### Diagnóstico direto com Docker Compose

```bash
docker compose ps
docker compose logs -f winhood winhood-scanner-worker
docker compose restart
```

---

## 4. Verificação E2E Automatizada

- **Contra containers Docker em execução:**
  ```bash
  node scripts/verify-docker-local-web.mjs --base-url http://127.0.0.1:3000
  ```
- **Simulação standalone de produção (sobe `dist-server/server.mjs` + `dist-server/scanner-worker.mjs` com token Bearer, sem daemon Docker):**
  ```bash
  node scripts/verify-docker-local-web.mjs --self-hosted
  ```
