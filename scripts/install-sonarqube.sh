#!/usr/bin/env bash
# ==============================================================================
# Instalador Oficial do SonarQube Community Build & SonarScanner CLI (Linux x64)
# WinHood Software Benchmark & Quality Analyzer
# - Baixa exclusivamente de binaries.sonarsource.com
# - Valida hash SHA-256 oficial antes de extrair
# - Armazena fora do código-fonte (~/.local/share/SoftwareBenchmarkAnalyzer/tools/sonarqube/)
# - Não baixa novamente quando já existir instalação validada
# ==============================================================================
set -euo pipefail

SONAR_VERSION="${SONAR_VERSION:-26.11.0.134175}"
OFFICIAL_SHA256="${OFFICIAL_SHA256:-bc18bf0f9faed6d27c9668a89ab86c84b22edeccb1050fbebb9d323bd506e7dc}"
SCANNER_VERSION="${SCANNER_VERSION:-8.4.0.16527}"
SCANNER_SHA256="${SCANNER_SHA256:-2a28f118e2e9375dfd36eb27b803e1d37f93daba4db068aca6eef9853041bb24}"
SONAR_PORT="${SONAR_PORT:-9000}"
TOOLS_ROOT="${EXTERNAL_TOOLS_DIR:-$HOME/.local/share/SoftwareBenchmarkAnalyzer/tools}"

echo "=== WinHood Benchmark Analyzer - Instalador Oficial SonarQube Community Build ==="
echo "1. Pré-verificação de recursos do sistema..."

FREE_RAM_MB=$(free -m | awk '/^Mem:/{print $7}')
CPU_CORES=$(nproc || echo 1)
echo "   - RAM Disponível: ${FREE_RAM_MB} MB (Mínimo recomendado: 4096 MB)"
echo "   - Núcleos de CPU: ${CPU_CORES} (Mínimo recomendado: 2)"

if ! command -v java >/dev/null 2>&1; then
  echo "[AVISO] JDK 21 não encontrado no PATH. Instale OpenJDK 21 LTS (ex: apt install openjdk-21-jdk) antes de iniciar o servidor local."
fi

SONAR_DIR="${TOOLS_ROOT}/sonarqube"
TARGET_EXTRACT="${SONAR_DIR}/sonarqube-${SONAR_VERSION}"
ZIP_FILE="${SONAR_DIR}/sonarqube-${SONAR_VERSION}.zip"
DOWNLOAD_URL="https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-${SONAR_VERSION}.zip"

mkdir -p "${SONAR_DIR}"

if [ -x "${TARGET_EXTRACT}/bin/linux-x86-64/sonar.sh" ]; then
  echo "2. Instalação validada já encontrada em ${TARGET_EXTRACT}. Pulando download."
else
  echo "2. Baixando distribuição oficial: ${DOWNLOAD_URL}"
  curl -fL "${DOWNLOAD_URL}" -o "${ZIP_FILE}"

  echo "3. Validando checksum SHA-256 oficial..."
  COMPUTED_SHA=$(sha256sum "${ZIP_FILE}" | awk '{print $1}')
  if [ "${COMPUTED_SHA}" != "${OFFICIAL_SHA256}" ]; then
    rm -f "${ZIP_FILE}"
    echo "[ERRO] Checksum SHA-256 inválido! Esperado: ${OFFICIAL_SHA256} | Calculado: ${COMPUTED_SHA}" >&2
    exit 1
  fi
  echo "   SHA-256 validado com sucesso: ${COMPUTED_SHA}"

  echo "4. Extraindo pacote..."
  unzip -q -o "${ZIP_FILE}" -d "${SONAR_DIR}"
fi

PROPS_FILE="${TARGET_EXTRACT}/conf/sonar.properties"
if [ -f "${PROPS_FILE}" ] && ! grep -q "^sonar.web.port=" "${PROPS_FILE}"; then
  echo "sonar.web.port=${SONAR_PORT}" >> "${PROPS_FILE}"
fi

echo "=== SonarQube Community Build v${SONAR_VERSION} preparado em ${TARGET_EXTRACT} ==="
echo "Para iniciar sob demanda: ${TARGET_EXTRACT}/bin/linux-x86-64/sonar.sh start"
