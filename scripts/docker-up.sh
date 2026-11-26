#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env.docker"

WITH_SONAR=false
SKIP_BUILD=false

for arg in "$@"; do
  case "${arg}" in
    --with-sonar)
      WITH_SONAR=true
      ;;
    --no-build)
      SKIP_BUILD=true
      ;;
    -h|--help)
      cat <<'USAGE'
Uso: ./scripts/docker-up.sh [--with-sonar] [--no-build]

Opções:
  --with-sonar  Inicia também o perfil opcional sonar-local (http://localhost:9000)
  --no-build    Inicia os containers reutilizando imagens já construídas
USAGE
      exit 0
      ;;
    *)
      echo "[WinHood Docker] Argumento desconhecido: ${arg}" >&2
      echo "Uso: ./scripts/docker-up.sh [--with-sonar] [--no-build]" >&2
      exit 2
      ;;
  esac
done

generate_secret_hex32() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif command -v node >/dev/null 2>&1; then
    node -e "process.stdout.write(require('node:crypto').randomBytes(32).toString('hex'))"
  else
    od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
  fi
}

read_env_value() {
  local key="$1"
  grep -E "^${key}=" "${ENV_FILE}" 2>/dev/null | tail -n 1 | cut -d'=' -f2- | tr -d '\r' || true
}

upsert_env_key() {
  local key="$1"
  local value="$2"
  local tmp_file="${ENV_FILE}.tmp.$$"
  umask 077
  if grep -qE "^${key}=" "${ENV_FILE}" 2>/dev/null; then
    awk -v k="${key}" -v v="${value}" '
      BEGIN { replaced=0 }
      $0 ~ ("^" k "=") && replaced==0 { print k "=" v; replaced=1; next }
      { print }
    ' "${ENV_FILE}" > "${tmp_file}"
    mv "${tmp_file}" "${ENV_FILE}"
  else
    printf '\n%s=%s\n' "${key}" "${value}" >> "${ENV_FILE}"
  fi
  chmod 600 "${ENV_FILE}"
}

# 1. Pré-requisitos Docker
if ! command -v docker >/dev/null 2>&1; then
  echo "[WinHood Docker] Erro: comando 'docker' não encontrado no PATH." >&2
  echo "Instale o Docker Engine ou Docker Desktop: https://docs.docker.com/get-docker/" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "[WinHood Docker] Erro: o daemon do Docker não está em execução ou o usuário atual não tem permissão." >&2
  echo "Inicie o serviço Docker (ou Docker Desktop) e tente novamente." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "[WinHood Docker] Erro: Docker Compose v2 ('docker compose') não encontrado." >&2
  echo "Atualize o Docker Desktop ou instale o plugin docker-compose-plugin." >&2
  exit 1
fi

# 2. Preparação segura e não-destrutiva do .env.docker
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "[WinHood Docker] Criando ${ENV_FILE} com segredos criptográficos aleatórios (32 bytes)..."
  SECRET="$(generate_secret_hex32)"
  WORKER_TOKEN="$(generate_secret_hex32)"
  umask 077
  cat > "${ENV_FILE}" <<EOF
# Gerado automaticamente por scripts/docker-up.sh (não versione este arquivo)
WINHOOD_PORT=3000
WINHOOD_KEYSTORE_MASTER_SECRET=${SECRET}
WINHOOD_SCANNER_WORKER_TOKEN=${WORKER_TOKEN}
WINHOOD_SONAR_DOCKER_IMAGE=sonarqube:25.1.0.102122-community
EOF
  chmod 600 "${ENV_FILE}"
fi

# 3. Validação de configuração sem sobrescrever customizações do usuário
WINHOOD_PORT_VALUE="$(read_env_value 'WINHOOD_PORT')"
WINHOOD_PORT_VALUE="${WINHOOD_PORT_VALUE:-3000}"
if ! [[ "${WINHOOD_PORT_VALUE}" =~ ^[0-9]+$ ]] || (( WINHOOD_PORT_VALUE < 1024 || WINHOOD_PORT_VALUE > 65535 )); then
  echo "[WinHood Docker] Erro: WINHOOD_PORT inválido ('${WINHOOD_PORT_VALUE}'). Utilize uma porta entre 1024 e 65535." >&2
  exit 1
fi

SECRET_VALUE="$(read_env_value 'WINHOOD_KEYSTORE_MASTER_SECRET')"
if [[ -z "${SECRET_VALUE}" ]]; then
  echo "[WinHood Docker] Preenchendo WINHOOD_KEYSTORE_MASTER_SECRET ausente em ${ENV_FILE}..."
  upsert_env_key 'WINHOOD_KEYSTORE_MASTER_SECRET' "$(generate_secret_hex32)"
  SECRET_VALUE="$(read_env_value 'WINHOOD_KEYSTORE_MASTER_SECRET')"
fi
if [[ ${#SECRET_VALUE} -lt 32 ]]; then
  echo "[WinHood Docker] Erro: WINHOOD_KEYSTORE_MASTER_SECRET em .env.docker deve ter no mínimo 32 caracteres." >&2
  exit 1
fi

WORKER_TOKEN_VALUE="$(read_env_value 'WINHOOD_SCANNER_WORKER_TOKEN')"
if [[ -z "${WORKER_TOKEN_VALUE}" ]]; then
  echo "[WinHood Docker] Preenchendo WINHOOD_SCANNER_WORKER_TOKEN ausente em ${ENV_FILE}..."
  upsert_env_key 'WINHOOD_SCANNER_WORKER_TOKEN' "$(generate_secret_hex32)"
  WORKER_TOKEN_VALUE="$(read_env_value 'WINHOOD_SCANNER_WORKER_TOKEN')"
fi
if [[ ${#WORKER_TOKEN_VALUE} -lt 32 ]]; then
  echo "[WinHood Docker] Erro: WINHOOD_SCANNER_WORKER_TOKEN em .env.docker deve ter no mínimo 32 caracteres." >&2
  exit 1
fi

# 4. Validação do manifesto Compose e inicialização dos serviços
COMPOSE_ARGS=(--env-file "${ENV_FILE}")
if [[ "${WITH_SONAR}" == "true" ]]; then
  COMPOSE_ARGS+=(--profile sonar)
fi

UP_ARGS=(up -d)
if [[ "${SKIP_BUILD}" != "true" ]]; then
  UP_ARGS+=(--build)
fi

echo "[WinHood Docker] Validando configuração do docker-compose.yml..."
(cd "${ROOT_DIR}" && docker compose "${COMPOSE_ARGS[@]}" config -q)

echo "[WinHood Docker] Iniciando serviços WinHood (127.0.0.1:${WINHOOD_PORT_VALUE})..."
(cd "${ROOT_DIR}" && docker compose "${COMPOSE_ARGS[@]}" "${UP_ARGS[@]}")

# 5. Aguarda healthchecks reais do backend e integração com o scanner worker
HEALTH_URL="http://127.0.0.1:${WINHOOD_PORT_VALUE}/api/health"
CAPS_URL="http://127.0.0.1:${WINHOOD_PORT_VALUE}/api/scanner-worker/capabilities"
echo "[WinHood Docker] Aguardando healthcheck da aplicação em ${HEALTH_URL}..."

http_get() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 4 "${url}"
  elif command -v node >/dev/null 2>&1; then
    node -e "fetch(process.argv[1]).then(async (r)=>{if(!r.ok)process.exit(1);process.stdout.write(await r.text());}).catch(()=>process.exit(1))" "${url}"
  else
    return 1
  fi
}

MAX_ATTEMPTS=60
ATTEMPT=1
HEALTHY=false
while [[ ${ATTEMPT} -le ${MAX_ATTEMPTS} ]]; do
  if http_get "${HEALTH_URL}" >/dev/null 2>&1; then
    HEALTHY=true
    break
  fi
  sleep 2
  ATTEMPT=$((ATTEMPT + 1))
done

if [[ "${HEALTHY}" != "true" ]]; then
  echo "[WinHood Docker] Erro: healthcheck de ${HEALTH_URL} não respondeu dentro do tempo limite." >&2
  echo "Consulte os logs com: docker compose logs -f winhood winhood-scanner-worker" >&2
  exit 1
fi

WORKER_STATUS="não verificado"
if CAPS_JSON="$(http_get "${CAPS_URL}" 2>/dev/null || true)"; then
  if echo "${CAPS_JSON}" | grep -q '"workerReachable":true'; then
    WORKER_STATUS="conectado e autenticado"
  else
    WORKER_STATUS="indisponível (verifique logs do winhood-scanner-worker)"
  fi
fi

echo ""
echo "========================================================================"
echo "  WinHood Benchmarking Local-Web está pronto!"
echo "========================================================================"
echo "  Endereço Web:     http://localhost:${WINHOOD_PORT_VALUE}"
echo "  Scanner Worker:   ${WORKER_STATUS}"
if [[ "${WITH_SONAR}" == "true" ]]; then
  echo "  SonarQube Local:  http://localhost:9000"
fi
echo ""
echo "  Comandos úteis:"
echo "    Status:         docker compose ps"
echo "    Logs:           docker compose logs -f"
echo "    Reiniciar:      docker compose restart"
echo "    Encerrar:       ./scripts/docker-down.sh"
echo "    Bases offline:  ./scripts/docker-update-scanner-dbs.sh (opcional: Grype)"
echo "========================================================================"
