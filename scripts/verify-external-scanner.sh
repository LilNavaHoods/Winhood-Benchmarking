#!/usr/bin/env bash
set -euo pipefail
TARGET_URL="${1:-http://127.0.0.1:3000/api/health}"
echo "[WinHood] Verificando conectividade com servico de auditoria em: $TARGET_URL"
curl -fsSL "$TARGET_URL" || echo "[WinHood] Servico offline; utilize o modo CLI embarcado."
