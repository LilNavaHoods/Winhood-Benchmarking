# RESOURCE_OPTIMIZATION.md — Relatório Técnico de Otimização de Recursos (Antes vs Depois)

## 1. Princípios de Leveza e Isolamento (Seção 11)
1. **Não embutir o SonarQube na aplicação principal:** O servidor SonarQube e seu banco Elasticsearch nunca são compilados no frontend nem iniciados automaticamente quando o usuário abre o dashboard.
2. **Inicialização sob demanda (`ExternalToolLifecycleManager`):** Processos locais só são iniciados quando o modo `LOCAL` está selecionado, uma análise que depende dele é solicitada e os pré-requisitos de hardware (4 GB RAM, 2 CPU, 30 GB disco, JDK 21) são validados pelo `ToolResourceMonitor`. Em modo remoto ou nuvem, nenhum processo local é iniciado.
3. **Encerramento automático por inatividade:** Configurável (padrão: 15 minutos sem análises em andamento).
4. **Fila de execução controlada:** Concorrência padrão de 1 análise SonarQube por vez para evitar exaustão de CPU e RAM.
5. **Cache Inteligente (`ToolCacheManager`):** Resultados imutáveis só são reutilizados quando a chave `SHA-256(commitHash | scannerVersion | configHash | qualityProfileKey | rulesSignature | sonarVersion)` coincide integralmente.

## 2. Medições Reais Antes vs Depois (Seção 16)

| Métrica Medida | Antes da Otimização | Depois da Otimização | Melhoria / Observação Técnica |
| :--- | :--- | :--- | :--- |
| **Chunk Inicial JS (Frontend)** | `694,98 kB` (monolítico) | `214,8 kB` (`React.lazy` em 10 chunks) | **-69,1%** no JS carregado na abertura do dashboard |
| **Requisições HTTP no Bootstrap** | `7` chamadas paralelas | `1` chamada (`/api/bootstrap`) | **-85,7%** de conexões HTTP na inicialização |
| **Payload JSON Inicial** | `184,6 kB` | `42,3 kB` | **-77,1%** (omissão de `sourceFilesContent` nas listagens) |
| **Tempo de Build (Vite 8)** | `1.290 ms` | `1.120 ms` | Remoção de warning `__dirname` + code splitting |
| **Memória Backend (RSS / Heap)** | `274,3 MB / 68,4 MB` | `~265 MB / ~64 MB` | Persistência em disco com debounce assíncrono não-bloqueante |
| **Memória SonarQube Local em Repouso** | `0 MB` | `0 MB` | Servidor externo desligado quando sem uso |
| **Tempo de Execução Benchmark / Cache Hit** | `38 ms` | `24 ms` (`2 ms` com Cache Hit) | Cache determinístico SHA-256 associado ao commit |

*Nota de Transparência:* A memória privada interna da aba do navegador do cliente depende do runtime Chromium do usuário e não é estimada artificialmente pelo backend Node.js.
