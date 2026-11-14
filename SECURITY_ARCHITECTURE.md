# Arquitetura de Segurança (AppSec, RBAC, DPAPI, SSRF Guard & Sandbox)

## 1. Autenticação, Sessões, MFA e RBAC no Servidor
- **Bootstrap Inicial Seguro**: Token single-use gravado em `security/admin_bootstrap_token.txt` com permissão restrita (`0600`). Sem credenciais padrão hardcoded.
- **Senhas**: Hash `scrypt` (`N=16384, r=8, p=1`, salt aleatório de 16 bytes) e comparação `crypto.timingSafeEqual`.
- **MFA TOTP (RFC 6238)**: Segredos TOTP criptografados em repouso com AES-256-GCM e proteção contra replay de janela temporal.
- **Sessões e CSRF**: Cookie `winhood_session` (`HttpOnly`, `SameSite=Lax`) combinado com token CSRF por sessão validado em todas as rotas mutáveis (`POST`, `PUT`, `PATCH`, `DELETE`).
- **RBAC Server-Side**: Perfis `ADMIN`, `SECURITY_LEAD`, `QA_ENGINEER` e `AUDITOR` validados no servidor em cada rota; cabeçalhos `x-winhood-role` são ignorados fora de modo de teste.

## 2. Gerenciamento de Chaves e Proteção DPAPI no Windows
- `KeyManagementService.ts` gerencia chaves `EVIDENCE_HMAC`, `EVIDENCE_ED25519` e `TOKEN_VAULT_AES256`.
- No Windows (`process.platform === 'win32'`), a chave mestra do cofre é protegida por usuário via **Windows DPAPI (`ProtectedData::Protect` / `CurrentUser`)**.
- Suporta rotação de chaves (`POST /api/security/keys/rotate`) com re-criptografia automática dos tokens armazenados e preservação das chaves históricas para verificação de relatórios antigos.

## 3. Proteção Anti-SSRF (`SsrfGuard.ts`)
- Toda sonda HTTP de performance (`ControlledTestAndPerfRunner`) passa pelo `SsrfGuard`:
  - Exige cadastro prévio e autorização do host alvo.
  - Resolve DNS (`dns.lookup(..., { all: true })`) e bloqueia loopback (`127.0.0.0/8`, `::1`), RFC1918 (`10/8`, `172.16/12`, `192.168/16`), link-local/metadata (`169.254.169.254`), CGNAT, multicast e IPv4-mapped IPv6 (`::ffff:127.0.0.1`).
  - Fixa a conexão (`pinnedLookup`) ao IP validado contra DNS rebinding e desabilita redirecionamentos automáticos (`redirect: 'manual'`).

## 4. Isolamento de Execução (`SandboxExecutor.ts`)
- Código de terceiros nunca é executado diretamente no processo principal.
- Utiliza containers descartáveis (`--network=none --read-only --cap-drop=ALL`), `bwrap` ou subprocessos Node com `--permission` restrito ao diretório temporário e ambiente sanitizado, verificando a remoção completa do diretório temporário (`recoveryVerified`).
