# Relatório de Validação de Segurança da Plataforma (`SECURITY_VALIDATION_REPORT.md`)

- **Versão do WinHood:** `4.4.0`
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + endurecimento `PRODUCTION_SECURE` e matriz Auth/TOTP/Scrypt
- **Ambiente:** Linux x64, `Node.js v22.23.2`
- **Comandos executados:** `npm run test:security` (`23/23 PASS`), `node scripts/verify-npm-audit.mjs` (`PASSED`)
- **Estado de validação:** `PARTIALLY_VALIDATED` *(controles criptográficos, autenticação, SSRF, Path Traversal, Sandbox e governança NPM `VALIDATED` em Linux; chamadas nativas Windows DPAPI e Windows Hello WinRT em host Windows real permanecem `NOT_VALIDATED` neste container)*

---

## 1. Matriz de Controles de Segurança Verificados (`src/security/security.test.ts`)

| Controle | Implementação Técnica | Evidência de Teste Automatizado | Estado |
|---|---|---|---|
| **Keystore `PRODUCTION_SECURE` Fail-Closed** | Recusa inicializar ou abrir cofre `.kek` local quando `WINHOOD_KEYSTORE_MODE=PRODUCTION_SECURE` sem DPAPI, macOS Keychain, Linux Secret Service ou `WINHOOD_KEYSTORE_MASTER_SECRET`. | `security.test.ts` subteste #22 (`Phase 3 P0 Keystore fail-closed in PRODUCTION_SECURE`) PASS. | `VALIDATED` |
| **Segregação de Domínio de Segredos** | `assertSecretDomainSeparation()` bloqueia reutilização entre `WINHOOD_KEYSTORE_MASTER_SECRET`, `WINHOOD_EVIDENCE_HMAC_SECRET`, `WINHOOD_VAULT_SECRET` e proíbe `SONAR_SECRET_SALT` como chave mestra ou chave ativa de cofre. | `security.test.ts` subteste #22 PASS. | `VALIDATED` |
| **Trust Store Ed25519 Fisicamente Separado** | `trust-store.json` persistido fora de `keystore.json` com MAC vinculado à KEK e validação de janela temporal/revogação. | `security.test.ts` subtestes #10 e #22 PASS. | `VALIDATED` |
| **Matriz Completa Auth / TOTP / QR / Migração Scrypt** | QR Code PNG offline (`data:image/png;base64,...`), persistência em disco após restart, disable/re-enable TOTP, migração `scrypt:N=16384 -> N=32768`, rejeição de downgrade e preservação do arquivo em falha de escrita. | `security.test.ts` subteste #23 (`Phase 10 Auth/TOTP/Migration Matrix`) PASS. | `VALIDATED` |
| **WebAuthn FIDO2 / Windows Hello** | Priorização de `rpId` / `Origin`, verificação criptográfica P-256 (`ES256`), contador anti-replay `signCount`. | `security.test.ts` subtestes #20 e #21 PASS (fluxo WinRT nativo simulado no Linux; prompt biométrico Windows real `NOT_VALIDATED`). | `PARTIALLY_VALIDATED` |
| **Proteção SSRF (`SsrfGuard`)** | Bloqueio de loopback, RFC 1918, link-local (`169.254.169.254`), IPv6 privado e revalidação manual de cada redirect HTTP. | `security.test.ts` subteste #15 PASS. | `VALIDATED` |
| **Path Traversal, Symlink & Backup Oracle** | Confinamento de diretório, rejeição de `..`, symlinks e nomes inválidos em `ProjectBackupService` e upload de código-fonte. | `security.test.ts` subteste #11 PASS. | `VALIDATED` |
| **Execução Isolada (`SandboxExecutor`)** | `spawnSync` com `shell: false`, allowlist de binários, `PATH` higienizado e verificação pós-limpeza (`RECOVERY_VERIFIED`). | `security.test.ts` subtestes #6, #13 e #18 PASS. | `VALIDATED` |

---

## 2. Limitações de Segurança Declaradas

1. **Rollback Físico Local:** Sem TPM 2.0 ou serviço remoto de transparência (`hardwareTpmOrRemoteAnchorAvailable: false`), a restauração simultânea de `keystore.json`, `.seq` e `trust-store.json` por um atacante com acesso local de escrita não pode ser impedida exclusivamente por arquivos locais.
2. **Exceções Build-Time Governadas (`picomatch <= 4.0.7`):** 5 advisories transitivos de `vite@8.3.8` estão documentados e governados com validade até `2027-02-17T22:50:00Z` em `security/npm-audit-exceptions.json`.
