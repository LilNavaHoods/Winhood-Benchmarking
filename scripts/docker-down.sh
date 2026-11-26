#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env.docker"

PURGE_VOLUMES=false
CONFIRM_DATA_LOSS=false

for arg in "$@"; do
  case "${arg}" in
    --purge-volumes)
      PURGE_VOLUMES=true
      ;;
    --confirm-data-loss)
      CONFIRM_DATA_LOSS=true
      ;;
    -h|--help)
      cat <<'USAGE'
Uso: ./scripts/docker-down.sh [--purge-volumes --confirm-data-loss]

Por padrão, encerra os containers preservando todos os volumes persistentes
(winhood_data, winhood_scanner_cache e volumes opcionais do SonarQube).

Opções destrutivas:
  --purge-volumes --confirm-data-loss
      REMOVE permanentemente os volumes Docker, projetos, keystore local e relatórios.
USAGE
      exit 0
      ;;
    *)
      echo "[WinHood Docker] Argumento desconhecido: ${arg}" >&2
      exit 2
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "[WinHood Docker] Erro: comando 'docker' não encontrado no PATH." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "[WinHood Docker] Erro: Docker Compose v2 não encontrado." >&2
  exit 1
fi

if [[ "${PURGE_VOLUMES}" == "true" && "${CONFIRM_DATA_LOSS}" != "true" ]]; then
  echo "[WinHood Docker] AÇÃO DESTRUTIVA BLOQUEADA: --purge-volumes apaga o cofre criptografado, projetos e histórico." >&2
  echo "Se deseja realmente remover os volumes, execute:" >&2
  echo "  ./scripts/docker-down.sh --purge-volumes --confirm-data-loss" >&2
  exit 2
fi

COMPOSE_ARGS=(--profile sonar)
if [[ -f "${ENV_FILE}" ]]; then
  COMPOSE_ARGS+=(--env-file "${ENV_FILE}")
fi

DOWN_ARGS=(down --remove-orphans)
if [[ "${PURGE_VOLUMES}" == "true" ]]; then
  DOWN_ARGS+=(-v)
  echo "[WinHood Docker] Encerrando containers e REMOVENDO volumes persistentes..."
else
  echo "[WinHood Docker] Encerrando containers (volumes persistentes serão preservados)..."
fi

(cd "${ROOT_DIR}" && docker compose "${COMPOSE_ARGS[@]}" "${DOWN_ARGS[@]}")
echo "[WinHood Docker] Encerramento concluído."
