#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="${1:-./tools/external-scanner}"
mkdir -p "$INSTALL_DIR"
echo "[WinHood] Diretorio de scanner externo compativel com SARIF 2.1.0 preparado em: $INSTALL_DIR"
