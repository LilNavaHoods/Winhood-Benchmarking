#!/usr/bin/env bash
# ==============================================================================
# Script de Verificação de Saúde e Autenticação do SonarQube Community Build
# WinHood Software Benchmark & Quality Analyzer
# - Nunca usa token na URL ou linha de comando exposta; utiliza cabeçalho Bearer via SONAR_TOKEN
# ==============================================================================
set -euo pipefail

SONAR_HOST_URL="${SONAR_HOST_URL:-http://localhost:9000}"

echo "=== Verificando instância SonarQube em ${SONAR_HOST_URL} ==="

STATUS_JSON=$(curl -fsS "${SONAR_HOST_URL}/api/system/status" || echo '{"status":"UNREACHABLE"}')
echo "Resposta /api/system/status: ${STATUS_JSON}"

if echo "${STATUS_JSON}" | grep -q '"status":"UP"'; then
  echo "[OK] Servidor SonarQube está UP e operacional."
else
  echo "[AVISO] Servidor não está em estado UP."
  exit 1
fi

if [[ -n "${SONAR_TOKEN:-}" ]]; then
  AUTH_JSON=$(curl -fsS -H "Authorization: Bearer ${SONAR_TOKEN}" "${SONAR_HOST_URL}/api/authentication/validate")
  if echo "${AUTH_JSON}" | grep -q '"valid":true'; then
    echo "[OK] Autenticação Bearer (SONAR_TOKEN) validada com sucesso."
  else
    echo "[ERRO] Token rejeitado por /api/authentication/validate."
    exit 2
  fi
else
  echo "[INFO] Variável SONAR_TOKEN não definida; verificada apenas conectividade pública."
fi
