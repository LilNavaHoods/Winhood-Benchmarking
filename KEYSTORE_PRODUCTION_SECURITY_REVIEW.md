# Revisão de Segurança em Produção do Keystore (`KEYSTORE_PRODUCTION_SECURITY_REVIEW.md`)

- **Versão do WinHood:** `4.4.0` (`WINHOOD-ENVELOPE-V2`)
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + endurecimento Fase 3 e Fase 5
- **Ambiente de verificação:** Linux x64, `Node.js v22.23.2`
- **Arquivos auditados:** `src/security/KeyManagementService.ts`, `src/engine/evidenceProvenanceEngine.ts`, `src/security/security.test.ts`
- **Comando executado:** `npm run test:security` (`23/23 PASS`)
- **Estado de validação:** `PARTIALLY_VALIDATED` *(`PRODUCTION_SECURE` fail-closed, `HKDF_EXTERNAL_ENV`, segregação de segredos, Trust Store externo e migração legada `VALIDATED` em Linux; chamadas nativas Windows DPAPI e macOS Keychain em hosts físicos Windows/macOS permanecem `NOT_VALIDATED` neste container)*

---

## 1. Comportamento Fail-Closed em `PRODUCTION_SECURE`

Em `src/security/KeyManagementService.ts`:
- O modo operacional é resolvido por `resolveOperatingMode()`: retorna `PRODUCTION_SECURE` quando `WINHOOD_KEYSTORE_MODE=PRODUCTION_SECURE` ou quando `NODE_ENV=production`.
- **Ordem de resolução da KEK (Key Encryption Key):**
  1. `HKDF_EXTERNAL_ENV`: Variável canônica `WINHOOD_KEYSTORE_MASTER_SECRET` ($\ge 16$ caracteres) -> deriva `KEK_WRAP` via `crypto.hkdfSync('sha256', ...)`.
  2. `WINDOWS_DPAPI`: Em `win32`, protege/desprotege a semente de 256 bits via `System.Security.Cryptography.ProtectedData` (`CurrentUser`) usando `spawnSync(powershell.exe, ..., { shell: false })`.
  3. `MACOS_KEYCHAIN`: Em `darwin`, usa `/usr/bin/security` (`find-generic-password` / `add-generic-password`) com `shell: false`.
  4. `LINUX_SECRET_SERVICE`: Em `linux` com `DBUS_SESSION_BUS_ADDRESS`, usa `secret-tool` com `shell: false`.
- **Bloqueio Estrito de `.kek` Local em Produção:**
  - Se nenhum dos 4 mecanismos acima estiver disponível em `PRODUCTION_SECURE`, `KeyManagementService` lança `KEYSTORE_PRODUCTION_PROVIDER_REQUIRED`.
  - Se um arquivo `keystore.json` existente tiver `kekMechanism: 'HKDF_LOCAL_KEK_FILE'` e for aberto em `PRODUCTION_SECURE` sem `WINHOOD_KEYSTORE_MASTER_SECRET`, lança `KEYSTORE_PRODUCTION_LOCAL_KEK_REJECTED`.
  - Se em Windows (`win32`) o DPAPI falhar durante `PRODUCTION_SECURE` e `WINHOOD_KEYSTORE_MASTER_SECRET` não estiver configurado, lança `KEYSTORE_DPAPI_REQUIRED_IN_PRODUCTION`.

---

## 2. Segregação de Variáveis de Ambiente e Descontinuação de `SONAR_SECRET_SALT`

| Variável de Ambiente | Finalidade Exclusiva | Regra de Isolamento (`assertSecretDomainSeparation`) |
|---|---|---|
| `WINHOOD_KEYSTORE_MASTER_SECRET` | Segredo mestre externo para derivação HKDF da KEK do Keystore (`keystore.json` e `trust-store.json`). | Proibido ter o mesmo valor que `WINHOOD_EVIDENCE_HMAC_SECRET`, `WINHOOD_VAULT_SECRET` ou `SONAR_SECRET_SALT`. |
| `WINHOOD_EVIDENCE_HMAC_SECRET` | Segredo externo opcional para HMAC da trilha de evidências. | Isolado de todas as demais variáveis. |
| `WINHOOD_VAULT_SECRET` | Segredo externo para cifragem ativa de credenciais de integrações no cofre. | Isolado de todas as demais variáveis. |
| `SONAR_SECRET_SALT` | **Apenas leitura retrocompatível (`decrypt-only`)** de registros legados `ENV-VAULT-KEY`. | Rejeitado com `KEYSTORE_SECRET_DOMAIN_VIOLATION` se reutilizado como `WINHOOD_KEYSTORE_MASTER_SECRET` ou substituto ativo de `WINHOOD_VAULT_SECRET`. |
| `WINHOOD_MASTER_KEY_SECRET` | Alias legado de leitura/migração da KEK. | Emite aviso explícito em `securityWarnings` instruindo migração para `WINHOOD_KEYSTORE_MASTER_SECRET`. |

---

## 3. Separação Física do Trust Store Ed25519 e Limitações de Rollback

1. **Arquivo Independente `trust-store.json` (`PersistedTrustStore`):**
   - Armazena `rootAnchorFingerprintSha256`, `monotonicSequence`, `trustedPublicKeys` (`ACTIVE`, `ROTATED_VERIFY_ONLY`, `REVOKED`) e `integrityMacHex` calculado com subchave HKDF exclusiva (`winhood:kms:v2:trust-store-integrity`).
   - Qualquer adulteração direta de uma chave pública ou status em `keystore.json` ou `trust-store.json` invalida o `integrityMacHex` vinculado à KEK.
2. **Transparência sobre Proteção contra Rollback em Armazenamento Local:**
   - O campo `hardwareTpmOrRemoteAnchorAvailable` reporta honestamente `false`.
   - Enquanto `monotonicSequence` + `.seq` + `trust-store.json` detectam restaurações parciais ou dessincronizadas, um administrador local ou processo com permissão de escrita no diretório `.winhood_data/keys/` pode copiar e restaurar **todos os arquivos simultaneamente** para um snapshot anterior legítimo. Impedir esse vetor exige contador monotônico de hardware (TPM 2.0) ou ancoragem em serviço remoto externo.
