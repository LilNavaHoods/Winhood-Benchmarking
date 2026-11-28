#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# WinHood Docker — Atualização Controlada das Bases Offline (Grype + OSV-Scanner)
# Executa container efêmero separado do worker (com acesso externo restrito à
# atualização), valida integridade (ZIP + SHA-256), registra manifest.json com
# versão/data/expiração/hashes e aplica swap atômico no volume winhood_scanner_cache.
# Durante as análises, o winhood-scanner-worker monta este volume como read-only (:ro).
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "[WinHood Scanner DB] Erro: Docker não disponível ou daemon parado." >&2
  exit 1
fi

PROJECT_NAME="$(basename "${ROOT_DIR}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]//g')"
VOLUME_NAME="${WINHOOD_SCANNER_CACHE_VOLUME:-${PROJECT_NAME}_winhood_scanner_cache}"
OSV_ECOSYSTEMS="${WINHOOD_OSV_ECOSYSTEMS:-npm PyPI Go Maven NuGet crates.io}"
DB_TTL_DAYS="${WINHOOD_SCANNER_DB_MAX_AGE_DAYS:-30}"

if ! docker volume inspect "${VOLUME_NAME}" >/dev/null 2>&1; then
  echo "[WinHood Scanner DB] Criando volume ${VOLUME_NAME}..."
  docker volume create "${VOLUME_NAME}" >/dev/null
fi

if ! docker image inspect winhood-scanner-worker:4.4.0 >/dev/null 2>&1; then
  echo "[WinHood Scanner DB] Construindo imagem winhood-scanner-worker:4.4.0..."
  (cd "${ROOT_DIR}" && docker compose build winhood-scanner-worker)
fi

echo "[WinHood Scanner DB] Atualizando base offline do Grype + OSV-Scanner no volume ${VOLUME_NAME}..."
docker run --rm \
  --user winhood \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -e GRYPE_DB_CACHE_DIR=/data/scanner-cache/grype \
  -e GRYPE_DB_AUTO_UPDATE=true \
  -e WINHOOD_OSV_DB_DIR=/data/scanner-cache/osv \
  -e OSV_ECOSYSTEMS="${OSV_ECOSYSTEMS}" \
  -e DB_TTL_DAYS="${DB_TTL_DAYS}" \
  -v "${VOLUME_NAME}:/data/scanner-cache" \
  winhood-scanner-worker:4.4.0 \
  bash -euo pipefail -c '
    # 1. Atualizar Grype DB em staging e instalar atomicamente
    GRYPE_STAGE="/data/scanner-cache/.grype-stage-$$"
    rm -rf "${GRYPE_STAGE}"
    mkdir -p "${GRYPE_STAGE}" /data/scanner-cache/grype
    GRYPE_DB_CACHE_DIR="${GRYPE_STAGE}" /usr/local/bin/grype db update
    GRYPE_DB_CACHE_DIR="${GRYPE_STAGE}" /usr/local/bin/grype db status >/dev/null
    node -e "
      const fs = require(\"node:fs\");
      const path = require(\"node:path\");
      const crypto = require(\"node:crypto\");
      const stage = process.argv[1];
      const ttlDays = Number(process.argv[2]) || 30;
      const artifacts = [];
      const walk = (dir) => {
        for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
          const full = path.join(dir, e.name);
          if (e.isDirectory()) walk(full);
          else if (e.isFile() && e.name !== \"manifest.json\") {
            const buf = fs.readFileSync(full);
            artifacts.push({
              relativePath: path.relative(stage, full).replace(/\\\\/g, \"/\"),
              sizeBytes: buf.length,
              sha256: crypto.createHash(\"sha256\").update(buf).digest(\"hex\"),
            });
          }
        }
      };
      walk(stage);
      if (artifacts.length === 0) process.exit(1);
      const now = new Date();
      const expiresAt = new Date(now.getTime() + ttlDays * 86400 * 1000).toISOString();
      const manifest = {
        schemaVersion: \"1.0.0\",
        tool: \"grype\",
        updatedAt: now.toISOString(),
        expiresAt,
        artifacts,
      };
      fs.writeFileSync(path.join(stage, \"manifest.json\"), JSON.stringify(manifest, null, 2));
    " "${GRYPE_STAGE}" "${DB_TTL_DAYS}"
    rm -rf /data/scanner-cache/grype.prev
    if [ -d /data/scanner-cache/grype ]; then mv /data/scanner-cache/grype /data/scanner-cache/grype.prev; fi
    mv "${GRYPE_STAGE}" /data/scanner-cache/grype
    rm -rf /data/scanner-cache/grype.prev

    # 2. Atualizar OSV-Scanner offline ZIPs por ecossistema em staging com validação ZIP + SHA-256
    OSV_STAGE="/data/scanner-cache/.osv-stage-$$"
    rm -rf "${OSV_STAGE}"
    mkdir -p "${OSV_STAGE}" /data/scanner-cache/osv
    for eco in ${OSV_ECOSYSTEMS}; do
      ECO_DIR="${OSV_STAGE}/${eco}"
      mkdir -p "${ECO_DIR}"
      ZIP_PATH="${ECO_DIR}/all.zip"
      curl --proto "=https" --tlsv1.2 -fsSL \
        "https://osv-vulnerabilities.storage.googleapis.com/${eco}/all.zip" \
        -o "${ZIP_PATH}"
      python3 -m zipfile -t "${ZIP_PATH}"
    done
    node -e "
      const fs = require(\"node:fs\");
      const path = require(\"node:path\");
      const crypto = require(\"node:crypto\");
      const stage = process.argv[1];
      const ttlDays = Number(process.argv[2]) || 30;
      const artifacts = [];
      const walk = (dir) => {
        for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
          const full = path.join(dir, e.name);
          if (e.isDirectory()) walk(full);
          else if (e.isFile() && e.name.endsWith(\".zip\")) {
            const buf = fs.readFileSync(full);
            artifacts.push({
              relativePath: path.relative(stage, full).replace(/\\\\/g, \"/\"),
              sizeBytes: buf.length,
              sha256: crypto.createHash(\"sha256\").update(buf).digest(\"hex\"),
            });
          }
        }
      };
      walk(stage);
      if (artifacts.length === 0) process.exit(1);
      const now = new Date();
      const expiresAt = new Date(now.getTime() + ttlDays * 86400 * 1000).toISOString();
      const manifest = {
        schemaVersion: \"1.0.0\",
        tool: \"osv-scanner\",
        updatedAt: now.toISOString(),
        expiresAt,
        ecosystems: artifacts.map((a) => a.relativePath.split(\"/\")[0]),
        artifacts,
      };
      fs.writeFileSync(path.join(stage, \"manifest.json\"), JSON.stringify(manifest, null, 2));
    " "${OSV_STAGE}" "${DB_TTL_DAYS}"
    rm -rf /data/scanner-cache/osv.prev
    if [ -d /data/scanner-cache/osv ]; then mv /data/scanner-cache/osv /data/scanner-cache/osv.prev; fi
    mv "${OSV_STAGE}" /data/scanner-cache/osv
    rm -rf /data/scanner-cache/osv.prev
  '

echo "[WinHood Scanner DB] Bases offline do Grype e OSV-Scanner atualizadas, validadas (SHA-256) e instaladas atomicamente em ${VOLUME_NAME}."
