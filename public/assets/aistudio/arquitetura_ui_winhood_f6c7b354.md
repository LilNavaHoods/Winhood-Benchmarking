# WinHood - Arquitetura de Interface e Design Tokens

Este documento define as diretrizes de estilo, paleta de cores, tipografia e estruturas de layout para o frontend do projeto WinHood, desenvolvido em React 19 e Tailwind CSS.

## 1. Identidade Visual e Cores (Design Tokens)

O projeto adota uma estética limpa, focada em utilidade (Dark Mode por padrão), utilizando tons de grafite contrastados com detalhes luminosos em ciano.

### Paleta Principal
*   **Theme Color (Global):** `#000000` (Preto puro, definido na meta tag)
*   **Accent Color (Destaque):** `#31d6c4` (Ciano) 
    *   *Uso:* Indicadores de foco, botões de ação principal, thumbs de scrollbar.
    *   *Variável CSS:* `--accent: #31d6c4;`
*   **Fundo de Interface (Grafite Translucido):** `rgba(21, 27, 36, 0.7)`
    *   *Uso:* Trilhas de scrollbar, fundos de modais sobrepostos e painéis secundários.

## 2. Tipografia

A tipografia deve garantir legibilidade em interfaces escuras e precisão em painéis de dados.

*   **Fonte Padrão:** Sans-serif moderna (padrão do sistema ou inter, via Tailwind).
*   **Dados e Métricas:** Para contadores, tempos e dados em painéis (ex: Auditor de Persistência), utilizar **variantes monoespaçadas tabulares**.
    *   *Classe Tailwind:* `tabular-nums`
    *   *Objetivo:* Manter os números perfeitamente alinhados verticalmente durante atualizações dinâmicas.

## 3. Configurações de Layout e Componentes

A organização do layout é modular, feita para acomodar ferramentas complexas sem poluir a interface.

*   **Containers de Ferramentas:** Utilizar estruturação baseada em abas (tabs) dedicadas, combinadas com visualizações em grade (grid) ou lista (flex/list), dependendo da densidade da informação.
*   **Modais e Painéis Sobrepostos:** Elementos de contexto isolado, como alertas e configurações rápidas.
*   **Assistentes Guiados (Wizards):** Interfaces multi-passos (ex: Rotina de otimização de boot) devem usar transições suaves entre as etapas, mantendo o usuário focado na tarefa atual.

## 4. Comportamento Global e Interatividade (Scrollbars)

A experiência de rolagem é customizada para manter a estética "limpa" da aplicação.

*   **Scrollbars Globais:** Ocultas por padrão. 
    *   *Regra CSS global:* `display: none;` para barras de rolagem na barra lateral e no *shell* principal do app.
*   **Scrollbars Contextuais (Classe `.df-hover-scroll`):**
    *   Aparecem apenas em áreas de opções de ferramentas quando o usuário passa o cursor (`:hover`).
    *   *Largura:* Fina (`6px`).
    *   *Thumb (Indicador):* Arredondado, utilizando a cor de destaque Ciano (`#31d6c4`).
    *   *Trilha (Track):* Grafite translúcido (`rgba(21, 27, 36, 0.7)`).
    *   *Animação:* Transição suave de opacidade (fade in/out).

## 5. Exemplo de Configuração (Tailwind e CSS)

```css
/* globais.css */
:root {
  --accent: #31d6c4;
  --bg-graphite-alpha: rgba(21, 27, 36, 0.7);
}

/* Ocultar scrollbar global */
::-webkit-scrollbar {
  display: none;
}

/* Scrollbar Contextual ao passar o mouse */
.df-hover-scroll {
  overflow-y: auto;
  scrollbar-width: thin; /* Firefox */
  scrollbar-color: transparent transparent;
  transition: scrollbar-color 0.3s ease;
}

.df-hover-scroll:hover {
  scrollbar-color: var(--accent) var(--bg-graphite-alpha);
}

.df-hover-scroll::-webkit-scrollbar {
  width: 6px;
  display: block;
}

.df-hover-scroll::-webkit-scrollbar-track {
  background-color: transparent;
}

.df-hover-scroll:hover::-webkit-scrollbar-track {
  background-color: var(--bg-graphite-alpha);
}

.df-hover-scroll::-webkit-scrollbar-thumb {
  background-color: transparent;
  border-radius: 9999px;
}

.df-hover-scroll:hover::-webkit-scrollbar-thumb {
  background-color: var(--accent);
}
```