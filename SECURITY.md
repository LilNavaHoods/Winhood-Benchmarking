# Política de Segurança e Divulgação Responsável (SECURITY.md)

## 1. Versões Suportadas

A equipe **WinHood Engineering & AppSec** fornece correções de segurança e atualizações de dependências para as seguintes versões do **WinHood Benchmark Analyzer**:

| Versão | Status de Suporte |
| :--- | :--- |
| **4.4.x** | Suportada ativamente (Atualizações de segurança e AppSec) |
| **4.0.x – 4.3.x** | Recomendada atualização para `4.4.0+` |
| **< 4.0.0** | Não suportada |

---

## 2. Arquitetura de Segurança Integrada

O WinHood implementa controles de defesa em profundidade verificados por suíte automatizada (`npm run test:security` e `npm run test:desktop`):

- **Criptografia em Repouso (`whdb:enc:v2`):** AES-256-GCM autenticado com rotação de chaves via `KeyManagementService` e verificação de integridade lateral SHA-256.
- **Autenticação Forte:** Senha/PIN com `scrypt` (`N=16384, r=8, p=1`), MFA TOTP RFC 6238 criptografado em repouso, **Login Social GitHub OAuth 2.0 + PKCE S256** (com `state` criptográfico vinculado a cookie `HttpOnly` em fluxo redirect, anti-replay single-use de `state` e `code`, proteção contra *session fixation*, `Client Secret` estritamente no backend e controle `WINHOOD_GITHUB_ALLOW_SIGNUP`) e suporte nativo a **Windows Hello (WebAuthn / FIDO2)** com validação criptográfica `ES256`/`RS256` e contador anti-replay (`signCount`).
- **Isolamento Electron:** `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, `webSecurity: true`, validação de origem loopback no IPC e bloqueio de navegação externa.
- **Proteção de Rede e Arquivos:** `SsrfGuard` contra acesso a IPs privados/loopback/metadata, proteção CSRF (`Double-Submit`), headers HTTP restritivos (`X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: no-referrer`, `Permissions-Policy`) e prevenção de Path Traversal / Zip Slip.

---

## 3. Como Reportar uma Vulnerabilidade (Divulgação Responsável)

Se você identificar uma vulnerabilidade de segurança no WinHood Benchmark Analyzer, **não abra uma issue pública** imediatamente. Siga o fluxo de divulgação coordenada:

1. **Envie um relatório de segurança** diretamente pela aba **Security Advisories** do repositório oficial no GitHub (`https://github.com/LilNavaHoods/Winhood-Benchmarking/security/advisories`) ou abra um relato técnico em **GitHub Issues** (`https://github.com/LilNavaHoods/Winhood-Benchmarking/issues`).
2. Inclua no relato:
   - Descrição técnica do problema e componente afetado (`server.ts`, `AuthService.ts`, `SandboxExecutor.ts`, `electron-main.ts`, etc.).
   - Passos claros para reprodução (PoC mínimo).
   - Impacto potencial estimado (CIA / CVSS).
3. **Prazo de Resposta:**
   - Confirmação de recebimento em até **48 horas**.
   - Triagem técnica e plano de correção em até **7 dias corridos**.
   - Publicação do patch e crédito ao pesquisador após disponibilização da versão corrigida.
