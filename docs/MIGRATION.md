# Guia de Migração de Configurações — WinHood Benchmarking v4.4.0 (`docs/MIGRATION.md`)

Este guia orienta desenvolvedores e equipes de DevSecOps na atualização de arquivos de configuração, pipelines de CI/CD e integrações de IDE para a nomenclatura independente introduzida na versão **4.4.0** do **WinHood Benchmarking**.

> **Garantia de Retrocompatibilidade (Zero Breaking Changes):** Todas as chaves e identificadores anteriores continuam sendo aceitos de forma transparente pelo motor, pela CLI e pela API REST OpenAPI 3.0.3.

---

## 1. Atualização do Nome do Modo de Análise e Perfis

Na versão `4.4.0`, o regime multidimensional de avaliação passou a adotar nomenclatura própria da plataforma:

| Configuração / Conceito | Identificador Legado (Ainda Aceito) | Novo Identificador Canônico (v4.4.0+) |
| :--- | :--- | :--- |
| **Nome de Exibição do Modo** | Modo MQR Legado | **`Modo MQR (Modern Quality Regime)`** |
| **Perfil de Qualidade** | `qg-sonar-way-mqr` / `sonar-way-ts-mqr-2026` | **`mqr-strict`** / **`Perfil de Qualidade Estrita`** |
| **Quality Gate Padrão** | `winhood-standard-v2` | **`winhood-standard-v2`** (inalterado) |
| **Quality Gate Zero-Trust** | `winhood-zero-trust-v2` | **`winhood-zero-trust-v2`** (inalterado) |
| **Tag de Domínio Padrão** | `mqr-legacy` | **`mqr-strict`** |

---

## 2. Atualização no `settings.json` do VS Code

Se você utilizava a configuração anterior da extensão de IDE, atualize seu `.vscode/settings.json` para incluir o novo campo `winhood.analysisProfile` e o fallback offline:

```json
{
  "winhood.apiBaseUrl": "http://localhost:3000",
  "winhood.apiToken": "",
  "winhood.analysisProfile": "mqr-strict",
  "winhood.qualityGateId": "winhood-standard-v2",
  "winhood.offlineCliFallback": true
}
```

---

## 3. Atualização em Pipelines de CI/CD

### 3.1 CLI (`winhood report` e `--ci-exit-codes`)
- Para gerar relatórios assinados em qualquer um dos quatro formatos oficiais, utilize o novo subcomando:
  ```bash
  npx tsx cli/winhood-cli.ts report --format=pdf --path . --gate winhood-standard-v2 --out relatorio.pdf
  npx tsx cli/winhood-cli.ts report --format=html --path . --gate winhood-standard-v2 --out relatorio.html
  npx tsx cli/winhood-cli.ts report --format=sarif --path . --gate winhood-standard-v2 --out relatorio.sarif
  npx tsx cli/winhood-cli.ts report --format=json --path . --gate winhood-standard-v2 --out relatorio.json
  ```
- Para habilitar a tabela canônica de 5 códigos de saída em pipelines (`0=APPROVED`, `1=APPROVED_WITH_RESERVATIONS`, `2=BLOCKED`, `3=INCONCLUSIVE`, `4=ERROR`), adicione `--ci-exit-codes` ao comando `winhood gate`. Sem essa flag, o comportamento anterior (`0/1/2/3`) permanece inalterado.

---

## 4. Mapeamento de Documentação Renomeada

- Antigo manual de API -> [`API_REFERENCE.md`](../API_REFERENCE.md)
- Antigo manual de IDE -> [`IDE_INTEGRATION.md`](../IDE_INTEGRATION.md)
- Antigo manual de integração externa -> [`EXTERNAL_INTEGRATION.md`](../EXTERNAL_INTEGRATION.md)
- Antigo manual de metodologia -> [`MQR_METHODOLOGY.md`](../MQR_METHODOLOGY.md)
- Novo glossário oficial -> [`GLOSSARY.md`](../GLOSSARY.md)
