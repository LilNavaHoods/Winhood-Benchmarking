# SONARQUBE_INSTALLATION.md — Guia de Download, Verificação Criptográfica e Instalação Oficial

## 1. Origem Oficial dos Binários
O **WinHood Software Benchmark & Quality Analyzer** utiliza exclusivamente as distribuições oficiais da **SonarSource**:
- **Portal Oficial de Download:** https://www.sonarsource.com/products/sonarqube/downloads/?modal=sonarqube-community-build-modal-form
- **Documentação Community Build:** https://docs.sonarsource.com/sonarqube-community-build/
- **Repositório de Distribuição Binária:** `https://binaries.sonarsource.com/Distribution/sonarqube/`

Não são utilizados repositórios de terceiros nem edições comerciais (Developer / Enterprise) para simular funcionalidades licenciadas.

## 2. Versão Identificada e Checksum SHA-256 Oficial
- **Produto:** SonarQube Community Build
- **Versão Estável Oficial:** `26.11.0.134175` (Lançamento: `2026-11-04T15:13:10Z`)
- **URL Oficial do Pacote ZIP:** `https://binaries.sonarsource.com/Distribution/sonarqube/sonarqube-26.11.0.134175.zip`
- **Tamanho do Pacote:** `915.316.171` bytes (~872,9 MB)
- **Hash SHA-256 Oficial (`sonarqube-26.11.0.134175.zip.sha256`):**
  `bc18bf0f9faed6d27c9668a89ab86c84b22edeccb1050fbebb9d323bd506e7dc`
- **Licença:** GNU Lesser General Public License v3.0 (LGPLv3)

## 3. Requisitos de Execução (Pré-Verificados pelo `ToolResourceMonitor`)
- **Java Runtime:** OpenJDK / Eclipse Temurin **JDK 21 LTS (64-bit)**
- **Memória RAM:** Mínimo de **4 GB de RAM livre** dedicados (2 GB para Elasticsearch, 1 GB para Compute Engine, 1 GB para Web Server). A plataforma nunca reduz arbitrariamente a memória da JVM para forçar inicialização em máquinas sem recursos.
- **CPU:** Mínimo de **2 núcleos**
- **Armazenamento:** Mínimo de **30 GB livres**
- **Parâmetros de Kernel (Linux):** `vm.max_map_count >= 524288` e `fs.file-max >= 131072`

## 4. Diretório Externo de Ferramentas
Os binários nunca são armazenados dentro do código-fonte versionado da aplicação:
- **Windows:** `%LOCALAPPDATA%\SoftwareBenchmarkAnalyzer\tools\sonarqube\`
- **Linux / macOS:** `~/.local/share/SoftwareBenchmarkAnalyzer/tools/sonarqube/`
- **Variável de sobrescrita:** `EXTERNAL_TOOLS_DIR`

## 5. Compatibilidade com o Google AI Studio e Scripts para o Host do Usuário
O ambiente de preview do Google AI Studio roda em um container Linux `4.19.0-gvisor` sem JDK 21 instalado e sem permissão de kernel para `sysctl vm.max_map_count=524288`. Conforme a Seção 2.4 da especificação, o sistema **não simula uma instalação concluída** neste container; em vez disso:
1. Fornece scripts automatizados que baixam, validam o SHA-256 e extraem no computador/servidor do usuário:
   - **Windows PowerShell:** `powershell -ExecutionPolicy Bypass -File scripts/install-sonarqube.ps1`
   - **Linux Bash:** `bash scripts/install-sonarqube.sh`
   - **Script de Verificação:** `SONAR_TOKEN="seu_token" bash scripts/verify-sonarqube.sh`
2. Permite conectar imediatamente a qualquer servidor SonarQube remoto (Modo 2) ou SonarQube Cloud.
