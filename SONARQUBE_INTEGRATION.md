# SONARQUBE_INTEGRATION.md — Arquitetura de Integração SonarQube

## 1. Visão Geral da Arquitetura
A camada independente `SonarQubeIntegrationService` (`src/integrations/sonarqube/SonarQubeAdapter.ts`) integra o **WinHood Software Benchmark & Quality Analyzer** ao SonarQube Community Build sem copiar a interface do SonarQube, utilizando seus resultados para enriquecer a comparação técnica entre **Software A** e **Software B**.

Fluxo de dados:
`Frontend -> Backend API -> Benchmark Orchestrator -> SonarQube Adapter -> SonarScanner -> SonarQube Community Build -> Web API -> Normalização -> Banco de Dados -> Dashboard Comparativo`

O frontend nunca executa diretamente processos do SonarScanner nem tem acesso aos tokens de autenticação.

## 2. Modos de Operação Suportados
- **Modo 1 — Servidor Local (`LOCAL`):** Conecta a `http://localhost:9000` (porta configurável). Inicia sob demanda apenas quando o usuário dispara uma análise e os pré-requisitos de hardware/JVM são atendidos.
- **Modo 2 — Servidor Remoto (`REMOTE`):** Conecta a uma instância corporativa existente informando URL e `SONAR_TOKEN`, dispensando qualquer processo local.
- **Modo 3 — SonarQube Cloud (`CLOUD`):** Adaptador opcional SaaS (`https://sonarcloud.io`) mediante consentimento explícito.

## 3. Máquina de Estados (`probeSonarQube()`)
Implementada em `src/integrations/sonarqube/SonarQubeConnection.ts`, a função `probeSonarQube()` valida conectividade HTTP real (`/api/system/status`) e autenticação (`/api/authentication/validate`), retornando um dos 10 estados canônicos:
- `NOT_INSTALLED`
- `NOT_CONFIGURED`
- `CONNECTING`
- `CONNECTED`
- `AUTH_FAILED`
- `SERVER_UNAVAILABLE`
- `VERSION_UNSUPPORTED`
- `READY`
- `RUNNING`
- `ERROR`

## 4. Comparação Padronizada A/B
Cada benchmark executa as análises de Software A e Software B sequencialmente na mesma instância, garantindo:
- Mesma versão do SonarQube (`26.11.0.134175`)
- Mesma versão do scanner apropriado
- Mesmo Quality Profile (`Sonar way`)
- Mesmo Quality Gate (`Sonar way (Padronizado A/B)`)
- Separação explícita entre métricas `SONARQUBE_NATIVE`, `EXTERNAL_TEST_REPORT_IMPORTED` e `BENCHMARK_CALCULATED`.
