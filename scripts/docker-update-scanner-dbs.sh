#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# WinHood Docker — Atualização Sob Demanda das Bases Offline de Scanners (Grype)
# Executa um container efêmero com acesso à internet APENAS para baixar/atualizar
# o cache local no volume winhood_scanner_cache, mantendo o winhood-scanner-worker
# 100% isolado (sem acesso à internet) durante as análises de código.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "[WinHood Scanner DB] Erro: Docker não disponível ou daemon parado." >&2
  exit 1
fi

PROJECT_NAME="$(basename "${ROOT_DIR}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]//g')"
VOLUME_NAME="${WINHOOD_SCANNER_CACHE_VOLUME:-${PROJECT_NAME}_winhood_scanner_cache}"

if ! docker volume inspect "${VOLUME_NAME}" >/dev/null 2>&1; then
  echo "[WinHood Scanner DB] Criando volume ${VOLUME_NAME}..."
  docker volume create "${VOLUME_NAME}" >/dev/null
fi

if ! docker image inspect winhood-scanner-worker:4.4.0 >/dev/null 2>&1; then
  echo "[WinHood Scanner DB] Construindo imagem winhood-scanner-worker:4.4.0..."
  (cd "${ROOT_DIR}" && docker compose build winhood-scanner-worker)
fi

echo "[WinHood Scanner DB] Atualizando base offline do Grype no volume ${VOLUME_NAME}..."
docker run --rm \
  --user winhood \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -e GRYPE_DB_CACHE_DIR=/data/scanner-cache/grype \
  -e GRYPE_DB_AUTO_UPDATE=true \
  -v "${VOLUME_NAME}:/data/scanner-cache" \
  winhood-scanner-worker:4.4.0 \
  /usr/local/bin/grype db update

echo "[WinHood Scanner DB] Base offline do Grype atualizada com sucesso."
echo "[WinHood Scanner DB] Nota: para OSV-Scanner offline, copie dumps OSV locais para /data/scanner-cache/osv no volume ${VOLUME_NAME}."
