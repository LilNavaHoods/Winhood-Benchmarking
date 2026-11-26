#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env.docker"

WITH_SONAR=false
for arg in "$@"; do
  case "${arg}" in
    --with-sonar)
      WITH_SONAR=true
      ;;
    *)
      echo "[WinHood Docker] Argumento desconhecido: ${arg}" >&2
      echo "Uso: ./scripts/docker-up.sh [--with-sonar]" >&2
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

if ! command -v docker >/dev/null 2>&1; then
  echo "[WinHood Docker] Erro: Docker não encontrado no PATH. Instale o Docker Desktop ou Docker Engine." >&2
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "[WinHood Docker] Gerando ${ENV_FILE} com segredos criptográficos de alta entropia (32 bytes)..."
  SECRET="$(generate_secret_hex32)"
  WORKER_TOKEN="$(generate_secret_hex32)"
  umask 077
  cat > "${ENV_FILE}" <<EOF
WINHOOD_PORT=3000
WINHOOD_KEYSTORE_MASTER_SECRET=${SECRET}
WINHOOD_SCANNER_WORKER_TOKEN=${WORKER_TOKEN}
WINHOOD_SONAR_DOCKER_IMAGE=sonarqube:25.1.0.102122-community
EOF
  chmod 600 "${ENV_FILE}"
fi

# Carrega variáveis do .env.docker sem expor segredos no log
WINHOOD_PORT_VALUE="$(grep -E '^WINHOOD_PORT=' "${ENV_FILE}" | tail -n 1 | cut -d'=' -f2- | tr -d '\r' || true)"
WINHOOD_PORT_VALUE="${WINHOOD_PORT_VALUE:-3000}"

SECRET_VALUE="$(grep -E '^WINHOOD_KEYSTORE_MASTER_SECRET=' "${ENV_FILE}" | tail -n 1 | cut -d'=' -f2- | tr -d '\r' || true)"
if [[ ${#SECRET_VALUE} -lt 32 ]]; then
  echo "[WinHood Docker] Erro: WINHOOD_KEYSTORE_MASTER_SECRET em .env.docker deve ter no mínimo 32 caracteres." >&2
  exit 1
fi

WORKER_TOKEN_VALUE="$(grep -E '^WINHOOD_SCANNER_WORKER_TOKEN=' "${ENV_FILE}" | tail -n 1 | cut -d'=' -f2- | tr -d '\r' || true)"
if [[ ${#WORKER_TOKEN_VALUE} -lt 32 ]]; then
  echo "[WinHood Docker] Adicionando WINHOOD_SCANNER_WORKER_TOKEN (>= 32 bytes) em ${ENV_FILE}..."
  WORKER_TOKEN_VALUE="$(generate_secret_hex32)"
  umask 077
  printf '\nWINHOOD_SCANNER_WORKER_TOKEN=%s\n' "${WORKER_TOKEN_VALUE}" >> "${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
fi

COMPOSE_ARGS=(--env-file "${ENV_FILE}")
if [[ "${WITH_SONAR}" == "true" ]]; then
  COMPOSE_ARGS+=(--profile sonar)
fi

echo "[WinHood Docker] Construindo e iniciando containers (127.0.0.1:${WINHOOD_PORT_VALUE})..."
(cd "${ROOT_DIR}" && docker compose "${COMPOSE_ARGS[@]}" up -d --build)

HEALTH_URL="http://127.0.0.1:${WINHOOD_PORT_VALUE}/api/health"
echo "[WinHood Docker] Aguardando healthcheck em ${HEALTH_URL}..."

MAX_ATTEMPTS=45
ATTEMPT=1
HEALTHY=false
while [[ ${ATTEMPT} -le ${MAX_ATTEMPTS} ]]; do
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS --max-time 3 "${HEALTH_URL}" >/dev/null 2>&1; then
      HEALTHY=true
      break
    fi
  elif command -v node >/dev/null 2>&1; then
    if node -e "fetch('${HEALTH_URL}').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" >/dev/null 2>&1; then
      HEALTHY=true
      break
    fi
  fi
  sleep 2
  ATTEMPT=$((ATTEMPT + 1))
done

if [[ "${HEALTHY}" != "true" ]]; then
  echo "[WinHood Docker] Aviso: healthcheck não respondeu dentro do tempo limite. Verifique: docker compose logs -f winhood" >&2
  exit 1
fi

echo ""
echo "WinHood Local-Web pronto em: http://localhost:${WINHOOD_PORT_VALUE}"
if [[ "${WITH_SONAR}" == "true" ]]; then
  echo "SonarQube Local (perfil sonar): http://localhost:9000"
fi
