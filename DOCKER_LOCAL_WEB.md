# WinHood Benchmarking — Modo Docker Local-Web (Sem Instalador `.exe`)

Execute a plataforma completa do **WinHood Benchmarking** (frontend React 19 + backend Express + banco cifrado persistente `WINHOOD-ENVELOPE-V2` + motores reais SAST/Taint/SCA/IaC/SBOM/Benchmarking + TOTP 2FA opcional) diretamente no navegador em **`http://localhost:3000`**, sem precisar compilar ou instalar executáveis `.exe` no Windows.

---

## 1. Requisitos

- **Docker Desktop** (Windows/macOS) ou **Docker Engine + Docker Compose v2** (Linux).
- Nenhuma conta externa, login obrigatório, OAuth ou senha inicial é exigida — o workspace abre diretamente em modo **Local-First irrestrito** (com TOTP 2FA opcional na barra superior).

---

## 2. Início Rápido em 1 Clique

### Windows (PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\docker-up.ps1
```

### Linux / macOS (Bash)

```bash
./scripts/docker-up.sh
```

O script executa automaticamente:
1. Cria `.env.docker` (caso ainda não exista) com um segredo mestre criptográfico CSPRNG de 32 bytes (`WINHOOD_KEYSTORE_MASTER_SECRET`) e permissão restrita (`0600` em Linux/macOS).
2. Executa `docker compose --env-file .env.docker up -d --build`.
3. Aguarda o healthcheck real (`GET /api/health`) ficar saudável.
4. Exibe o endereço pronto de acesso: `http://localhost:3000` (ou a porta configurada em `WINHOOD_PORT`).

> Para iniciar também a instância opcional do SonarQube Community local (`http://localhost:9000`), acrescente `--with-sonar` (Linux/macOS) ou `-WithSonar` (PowerShell).

---

## 3. Início Manual com Docker Compose

```bash
cp .env.docker.example .env.docker
# Edite .env.docker e defina WINHOOD_KEYSTORE_MASTER_SECRET (>= 32 bytes, ex.: openssl rand -hex 32)
docker compose --env-file .env.docker up -d --build
```

Com o perfil opcional do SonarQube local:

```bash
docker compose --env-file .env.docker --profile sonar up -d --build
```

---

## 4. Portas, Isolamento de Rede e Segurança do Container

- **Confinamento estrito no host**: `docker-compose.yml` publica a porta exclusivamente em `127.0.0.1:${WINHOOD_PORT:-3000}:3000` (e `127.0.0.1:9000:9000` no perfil `sonar`). O serviço **não** fica exposto para a rede local (LAN) por padrão.
- **Execução sem privilégios**: o container roda como usuário não-root `winhood` (`UID/GID 1001`), com `cap_drop: ["ALL"]`, `security_opt: ["no-new-privileges:true"]` e `init: true`.
- **Criptografia fail-closed**: o cofre (`KeyManagementService` em `PRODUCTION_SECURE`) exige `WINHOOD_KEYSTORE_MASTER_SECRET` com no mínimo 32 bytes de entropia via `.env.docker` (nunca versionado no Git).
- **Porta customizável**: basta alterar `WINHOOD_PORT=3080` em `.env.docker` e reiniciar o container; o CORS dinâmico do modo `LOCAL_WEB` autoriza automaticamente `http://localhost:3080` e `http://127.0.0.1:3080`.
- **TOTP 2FA opcional em `http://localhost`**: cookies `winhood_totp_unlock` (`HttpOnly; SameSite=Strict`) e `winhood_csrf` (`SameSite=Strict`) operam nativamente em loopback HTTP sem exigir TLS local.

---

## 5. Persistência de Dados, Backup e Encerramento Seguro

- Todos os projetos, execuções, chaves cifradas, evidências e logs ficam persistidos no volume nomeado **`winhood_data`** montado em `/data/winhood` (permissão `0700`).
- Ao parar o container (`docker compose down`), o servidor intercepta `SIGTERM`, executa o flush final atômico do banco persistente e encerra de forma limpa.
- Para backup do volume persistente:

```bash
docker run --rm -v winhood_data:/data:ro -v "$(pwd)":/backup alpine \
  tar czf /backup/winhood-data-backup.tar.gz -C /data .
```

- Para visualizar logs e status:

```bash
docker compose ps
docker compose logs -f winhood
```

- Para parar mantendo seus dados no volume `winhood_data`:

```bash
docker compose down
```
