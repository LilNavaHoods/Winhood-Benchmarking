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
- **Autenticação Forte & GitHub OAuth 2.0 + PKCE S256:**
  - Senha/PIN derivada com `scrypt` (`N=32768, r=8, p=1`, chave de 64 bytes) e MFA TOTP RFC 6238 criptografado em repouso.
  - **Login Social GitHub OAuth 2.0 (Authorization Code + PKCE S256):** redirecionamento direto na mesma aba (`/api/auth/github/oauth/start`), `state` criptográfico vinculado a cookie `HttpOnly` (`SameSite=Lax` em fluxo padrão, `Secure` em produção HTTPS, `SameSite=None; Secure; Partitioned` apenas em iframe hospedado), armazenamento criptografado anti-replay (`GitHubOAuthTransactionStore`) com invalidação single-use de `state` e `code`, rejeição de `redirect_uri` com query/fragmento ou aberto, `Cache-Control: no-store` nas rotas OAuth, rate limiting dedicado (`429`), rotação de sessão contra *session fixation*, limpeza de `winhood_oauth_state` no logout, `Client Secret` estritamente server-side (auditado contra vazamento em bundles `dist/` e respostas HTTP) e controle opcional `WINHOOD_GITHUB_ALLOW_SIGNUP`.
  - **Proteção no Cliente:** tokens de sessão não são gravados em `localStorage`; o cliente opera com cookies `HttpOnly` e cabeçalho CSRF Double-Submit (`x-winhood-csrf`).
  - **Windows Hello (WebAuthn / FIDO2):** validação criptográfica `ES256`/`RS256` e contador anti-replay (`signCount`).
- **Fronteira Browser-Safe Verificada em Build/CI:** `npm run check:browser-imports` impede que módulos Node-only (`node:child_process`, `node:fs`, `node:crypto`, `KeyManagementService`) sejam alcançáveis a partir do frontend.
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
