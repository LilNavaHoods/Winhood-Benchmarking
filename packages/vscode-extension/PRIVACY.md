# Política de Privacidade — Extensão VS Code WinHood (`PRIVACY.md`)

## 1. O Que é Enviado à API do WinHood
Quando os comandos `Winhood: Analisar arquivo atual` ou `Winhood: Analisar workspace` são acionados pelo desenvolvedor:
- A extensão lê apenas os arquivos de código-fonte elegíveis do workspace (excluindo `node_modules`, `.git` e diretórios de build) e os envia via requisição HTTP `POST /api/analyze/sarif` para a URL configurada em `winhood.apiBaseUrl` (por padrão `http://localhost:3000`, em loopback local).
- Segredos detectados durante a análise são imediatamente mascarados (`***REDACTED***`) pelo motor antes de qualquer persistência.

## 2. Modo Offline e Zero Telemetria Externa
- Quando a API em `winhood.apiBaseUrl` está indisponível e `winhood.offlineCliFallback` está ativo, a análise ocorre 100% localmente por meio do processo CLI embarcado, sem tráfego de rede.
- A extensão **não coleta telemetria de uso**, **não envia código-fonte para serviços de terceiros** e **não realiza chamadas externas ocultas**.
