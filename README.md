# WinHood — Software Benchmark & Quality Analyzer

Plataforma técnica full-stack para benchmarking comparativo de dois ou mais softwares de finalidade semelhante, realizando avaliações automatizadas de qualidade de código, segurança DevSecOps (SAST, SCA, Segredos, SBOM), acoplamento arquitetural, banco de dados SQL, equivalência funcional (QA), desempenho controlado, snapshots de instalação (T0/T1/T2) e validação pelo **Motor de Veracidade** com trilha de evidências imutável **SHA-256**.

---

## 1. Arquitetura Visual (WinHood Design System)

- **Theme Color Global:** `#000000` (Preto puro na meta tag, Dark Mode nativo `#080b10` / `#0f141c` e alternância Claro/Escuro).
- **Accent Color (Destaque):** `#31d6c4` (`--accent: #31d6c4`).
- **Fundo Grafite Translúcido:** `rgba(21, 27, 36, 0.7)` (`--bg-graphite-alpha`).
- **Tipografia:** `Plus Jakarta Sans` para estrutura de interface e `JetBrains Mono` com `tabular-nums` para alinhamento vertical estrito de métricas, notas `0.00–5.00`, latências e hashes SHA-256.
- **Scrollbars Contextuais (`.df-hover-scroll`):** Barras de rolagem globais ocultas por padrão e reveladas sob `:hover` com 6px em ciano `#31d6c4`.

---

## 2. Arquitetura Técnica e Módulos Implementados

1. **Gerenciamento de Projetos (`/api/projects`):** CRUD completo com UUID v4, categoria configurável, objetivo, responsável e histórico.
2. **Cadastro de Softwares e Ingestão Isolada (`/api/softwares`):** Armazenamento de artefatos em diretório isolado (`.winhood_data/isolated_artifacts/`), cálculo determinístico de hash SHA-256 por arquivo e por pacote, contagem real de linhas de código (LOC) e inventário por linguagem sem executar binários durante a ingestão.
3. **Assistente Guiado de Benchmark (Wizard 4 Etapas):**
   - Seleção de 2 ou mais softwares participantes.
   - Perfis reutilizáveis e validação matemática estrita dos pesos das 12 categorias (`Soma = 100%`).
   - Validação de equivalência experimental (vCPUs, RAM, SO, Concorrência e Autorização Formal DAST).
4. **Motor de Análise Estática & DevSecOps (`src/engine/staticAnalyzer.ts`):**
   - `opengrep-sast`: Detecção de SQL Injection, execução dinâmica (`eval`/`execSync`), criptografia fraca (`MD5`/`SHA-1`) e PRNG inseguro (`Math.random()`).
   - `gitleaks-secrets`: Detecção de segredos hardcoded com **mascaramento automático** nas evidências e relatórios.
   - `sonarqube-quality`: Complexidade ciclomática e cognitiva, blocos `catch` vazios, supressão de tipos (`any`), código duplicado e dívida técnica.
   - `syft-grype-sca`: Inspeção de dependências (`package.json`) com correlação CVE/CWE/CVSS/EPSS.
   - `archunit-cruiser`: Grafo de acoplamento aferente/eferente ($C_a, C_e$), instabilidade $I$, detecção de dependências circulares e violações de camada (`PRESENTATION -> DATABASE`).
   - `sqlfluff-db`: Auditoria de schemas SQL, projeções `SELECT *` e colunas de credenciais sem criptografia.
5. **Motor de Veracidade (`VeracityCheckResult`):** Executa 12 verificações obrigatórias antes de aprovar qualquer execução (`SUCCESS_VALIDATED`, `INCOMPLETE_COVERAGE`, `EMPTY_ERROR`, `VISUAL_ONLY`).
6. **Motor de Pontuação Determinística (`WINHOOD-DET-SCORE-v2.4.0`):** Calcula notas de `0.00` a `5.00` com **Travas Matemáticas (Penalty Caps / Kill Switches)** que impedem médias elevadas quando existem falhas críticas de segurança, cobertura incompleta ou funcionalidades essenciais ausentes.
7. **Relatórios e Exportação (`/api/reports/:runId/export`):** Geração de 10 modalidades de relatórios nos formatos JSON, CSV/Excel, Markdown e PDF imprimível.

---

## 3. Execução e Testes Automatizados

```bash
# Instalar dependências
npm install

# Executar suíte de testes unitários e de integração dos motores (node:test)
npx --yes tsx --test src/engine/analyzer.test.ts

# Iniciar servidor full-stack (Express API + Vite Frontend na porta 3000)
npm run dev
```
