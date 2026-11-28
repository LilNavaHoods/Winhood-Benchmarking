# Relatório de Capacidades dos Scanners — WinHood Benchmarking v4.4.0

- **Arquitetura de execução:** Worker isolado (`winhood-scanner-worker`) em rede Docker interna (`internal: true`, sem acesso à internet), sistema de arquivos raiz somente leitura (`read_only: true`), usuário não-root (`winhood`, UID/GID `1001`), `cap_drop: [ALL]` e `no-new-privileges:true`.
- **Imagem base pinada:** `node:22.21.1-bookworm-slim` (alinhada aos requisitos de runtime do Babel 8 e da stack TypeScript/ESLint).
- **Estado de validação:** Verificação estática de Dockerfiles/Compose, sintaxe Bash e testes unitários/integração do worker **`PASS`**; execução ao vivo dentro do daemon Docker **`NOT_EXECUTED`** neste sandbox (binário `docker` ausente).

---

## 1. Matriz Oficial: Scanners Empacotados vs Opcionais

### A. 8 Ferramentas Empacotadas no Worker (`Dockerfile.scanner-worker`)

| # | Ferramenta | Categoria | Versão Fixada | Integridade no Build | Modo Offline / Regras | Estado no Boot (Docker Padrão) |
|---|---|---|---|---|---|---|
| 1 | **Ruff** | Qualidade / Lint Python | `0.9.6` | Pip versão pinada em venv isolado | Nativo offline | `OPERATIONAL` |
| 2 | **Bandit** | SAST Python | `1.8.3` | Pip versão pinada em venv isolado | Nativo offline | `OPERATIONAL` |
| 3 | **Semgrep** | SAST multi-linguagem | `1.109.0` | Pip versão pinada em venv isolado | Regras embarcadas `/opt/winhood-scanner-rules/winhood-core.yaml`, `--disable-version-check`, `tmpfs` em `/home/winhood/.semgrep` e `/home/winhood/.cache` | `OPERATIONAL` |
| 4 | **Gitleaks** | Detecção de segredos | `8.24.0` | `curl --proto '=https' --tlsv1.2 -fsSL` + `sha256sum -c` | Execução com `--redact` + redação defensiva de payloads (`redactScannerPayloadSecrets`) | `OPERATIONAL` |
| 5 | **ESLint** | Qualidade / Segurança JS & TS | `9.21.0` | Instalação npm pinada (`ARG ESLINT_VERSION=9.21.0`) | Config flat embarcada zero-dependência `/opt/winhood-scanner-rules/eslint.config.mjs` (`WINHOOD_ESLINT_CONFIG_PATH`) | `OPERATIONAL` |
| 6 | **Syft** | Geração de SBOM (CycloneDX) | `1.20.0` | `curl --proto '=https' --tlsv1.2 -fsSL` + `sha256sum -c` | Nativo offline | `OPERATIONAL` |
| 7 | **Grype** | Correlação SCA offline | `0.89.0` | `curl --proto '=https' --tlsv1.2 -fsSL` + `sha256sum -c` | Exige cache offline íntegro em `/data/scanner-cache/grype` (`:ro`) com `manifest.json` (SHA-256 + TTL) | `DATABASE_UNAVAILABLE` até rodar `docker-update-scanner-dbs` |
| 8 | **OSV-Scanner** | SCA em lockfiles offline | `1.9.2` | `curl --proto '=https' --tlsv1.2 -fsSL` + `sha256sum -c` | Exige cache offline íntegro em `/data/scanner-cache/osv` (`:ro`) com `manifest.json` (SHA-256 + TTL) | `DATABASE_UNAVAILABLE` até rodar `docker-update-scanner-dbs` |

### B. 5 Ferramentas Externas Opcionais (Não Empacotadas na Imagem Slim)

| Ferramenta | Motivo da Não-Inclusão na Imagem Slim | Comportamento Honesto no Worker | Caminho de Integração |
|---|---|---|---|
| **CodeQL** | Binário proprietário/licenciamento específico e tamanho elevado | Reporta `NOT_INSTALLED` (`INCONCLUSIVE`, nunca "0 vulnerabilidades") | Importação de relatórios via **SARIF 2.1.0** |
| **Roslyn (.NET SDK)** | Tamanho do SDK .NET completo na imagem slim | Reporta `NOT_INSTALLED` | Importação via **SARIF 2.1.0** |
| **SpotBugs (JDK)** | Exige JDK + bytecode compilado do projeto-alvo | Reporta `NOT_INSTALLED` | Importação via **SARIF 2.1.0** |
| **Checkstyle (JDK)** | Exige runtime JVM dedicado | Reporta `NOT_INSTALLED` | Importação via **SARIF 2.1.0** |
| **Trivy** | Redundância operacional com Syft + Grype + OSV-Scanner já embarcados | Reporta `NOT_INSTALLED` | Importação via **SARIF 2.1.0** |

---

## 2. Hardening Aplicado ao Worker (`src/worker/scannerWorkerServer.ts` & `docker-compose.yml`)

1. **Semgrep em Container `read_only: true`:**
   - Adicionados mounts `tmpfs` (`noexec,nosuid`) para `/home/winhood/.semgrep` e `/home/winhood/.cache` em `docker-compose.yml` e diretórios pré-criados com ownership `winhood:winhood` em `Dockerfile.scanner-worker`.
   - Adicionado `PYTHONDONTWRITEBYTECODE=1`, `SEMGREP_SEND_METRICS=off`, `SEMGREP_SETTINGS_FILE` e `SEMGREP_VERSION_CACHE_PATH` em `buildSanitizedScannerEnv(workspaceDir)`, além da flag `--disable-version-check`.
2. **Montagem Somente Leitura do Cache Offline:**
   - `winhood_scanner_cache:/data/scanner-cache:ro` garante que jobs de análise nunca possam alterar ou envenenar as bases de vulnerabilidades durante a execução.
3. **Atualização Atômica Fora de Banda (Grype + OSV-Scanner):**
   - `scripts/docker-update-scanner-dbs.sh` e `scripts/docker-update-scanner-dbs.ps1` atualizam tanto a base do **Grype** quanto os arquivos oficiais do **OSV-Scanner** (`npm`, `PyPI`, `Go`, `Maven`, `NuGet`, `crates.io` via `https://osv-vulnerabilities.storage.googleapis.com/<ecossistema>/all.zip`).
   - Cada arquivo ZIP é validado com `python3 -m zipfile -t`, recebe hash `SHA-256` gravado em `manifest.json` (junto com `tool`, `updatedAt` e `expiresAt`), e só então é promovido por substituição atômica para o diretório ativo.
4. **Validação Estrita de Integridade e Validade (`validateOfflineDbManifest`):**
   - Antes de executar Grype ou OSV-Scanner, o worker valida a existência do `manifest.json`, correspondência do campo `tool`, validade temporal (`expiresAt > now`) e hash `SHA-256` de cada artefato listado.
   - Em caso de ausência, adulteração ou expiração, retorna explicitamente `DATABASE_UNAVAILABLE` (nunca `0 vulnerabilidades`).
5. **Prevenção de Vazamento de Segredos em Payloads:**
   - Gitleaks executa sempre com `--redact`.
   - `redactScannerPayloadSecrets(toolId, payload)` aplica redação defensiva em tempo linear O(n) para blocos PEM privados e tokens sensíveis antes da persistência criptografada.
6. **Auto-Testes Positivos e Negativos (`probeVerifiedWorkerCapabilities`):**
   - O probe de capacidades executa cenários positivos (código vulnerável esperado) e negativos (código limpo esperado) para confirmar funcionamento efetivo do scanner, evitando falsos estados `OPERATIONAL`.

---

## 3. Evidências de Testes de Regressão

- `src/security/remediationP0P1.test.ts` — **Teste 13 (`ScannerWorker-Hardening`)**: valida `buildSanitizedScannerEnv`, existência da config offline do ESLint, aprovação de `manifest.json` válido, rejeição de manifesto adulterado (SHA-256 divergente) e expirado (TTL vencido), e redação de segredos/blocos PEM no payload do Gitleaks (**`PASS`**).
- `src/security/backendHardening.test.ts` — validações estruturais de `Dockerfile`, `Dockerfile.scanner-worker`, `docker-compose.yml` e `scripts/docker-update-scanner-dbs.sh` (**`PASS`**).
- `bash -n scripts/docker-up.sh scripts/docker-down.sh scripts/docker-update-scanner-dbs.sh` (**`PASS`**).
- Execução real dos 8 scanners dentro do container `winhood-scanner-worker`: **`NOT_EXECUTED`** neste sandbox (requer host com Docker Engine / Docker Desktop).
