# Especificação da Arquitetura Criptográfica do Keystore (`KEYSTORE_SECURITY_DESIGN.md`)

- **Versão do WinHood:** `4.4.0` (`WINHOOD-ENVELOPE-V2`)
- **Commit base / Estado:** `d382a4e96a0481cba80f005790ab65100dfc5ae4` + endurecimento `PRODUCTION_SECURE` fail-closed
- **Ambiente:** Linux x64, `Node.js v22.23.2`
- **Implementação Principal:** `src/security/KeyManagementService.ts` e `src/engine/evidenceProvenanceEngine.ts`
- **Comando de verificação:** `npm run test:security` (`23/23 PASS`)
- **Estado de validação:** `PARTIALLY_VALIDATED` *(`HKDF_EXTERNAL_ENV`, Linux/macOS fallback detection, fail-closed `PRODUCTION_SECURE`, Trust Store externo e migração legada `VALIDATED`; provedores nativos Windows DPAPI e macOS Keychain exigem execução nos respectivos sistemas operacionais)*

---

## 1. Arquitetura de Criptografia por Envelope (`WINHOOD-ENVELOPE-V2`)

1. **DEK (Data Encryption Key):** 256 bits (`crypto.randomBytes(32)`) gerados por CSPRNG, sem qualquer dependência de atributos da máquina (`hostname`, `username` ou serial de disco).
2. **Modos Operacionais (`KeystoreOperatingMode`):**
   - `PRODUCTION_SECURE` (padrão quando `NODE_ENV=production` ou `WINHOOD_KEYSTORE_MODE=PRODUCTION_SECURE`): **Fail-Closed**. Exige obrigatoriamente um provedor seguro de SO ou segredo mestre explícito:
     - `WINDOWS_DPAPI` (`System.Security.Cryptography.ProtectedData::Protect`, escopo `CurrentUser`, invocado via `spawnSync` com `shell: false`);
     - `MACOS_KEYCHAIN` (`/usr/bin/security` com `shell: false`);
     - `LINUX_SECRET_SERVICE` (`secret-tool` sobre sessão D-Bus ativa com `shell: false`);
     - `HKDF_EXTERNAL_ENV` (`WINHOOD_KEYSTORE_MASTER_SECRET` com $\ge 16$ caracteres).
     - **Proibição de Fallback `.kek` em Produção:** Se nenhum dos 4 provedores acima estiver disponível em `PRODUCTION_SECURE`, o serviço lança erro `KEYSTORE_PRODUCTION_PROVIDER_REQUIRED` ou `KEYSTORE_PRODUCTION_LOCAL_KEK_REJECTED` e recusa inicializar ou ler um arquivo `.kek` local.
   - `DEVELOPMENT` / `RECOVERY`: Permite `HKDF_LOCAL_KEK_FILE` (`.keystore.kek.bin` com permissão `0600`) apenas fora de `PRODUCTION_SECURE`, emitindo alerta explícito em `securityWarnings`.

---

## 2. Segregação Estrita de Domínio de Segredos e Derivação HKDF (RFC 5869)

1. **Variáveis de Ambiente Segregadas (`assertSecretDomainSeparation`):**
   - `WINHOOD_KEYSTORE_MASTER_SECRET`: Segredo mestre exclusivo para derivar a KEK do Keystore.
   - `WINHOOD_EVIDENCE_HMAC_SECRET`: Segredo exclusivo para assinatura HMAC de evidências.
   - `WINHOOD_VAULT_SECRET`: Segredo exclusivo para cifragem do cofre de credenciais.
   - `SONAR_SECRET_SALT`: Reservado **exclusivamente** para descriptografia retrocompatível de registros legados (`ENV-VAULT-KEY`). É bloqueado (`KEYSTORE_SECRET_DOMAIN_VIOLATION`) se reutilizado como `WINHOOD_KEYSTORE_MASTER_SECRET` ou substituto ativo de `WINHOOD_VAULT_SECRET`.
   - `WINHOOD_MASTER_KEY_SECRET`: Aceito apenas como alias legado de leitura/migração, emitindo aviso de deprecação.
2. **Subchaves Derivadas via HKDF-SHA256 (`deriveHkdfPurposeKey`):**
   - `winhood:kms:v2:kek-wrap`: Cifragem/decifragem AES-256-GCM do envelope da DEK.
   - `winhood:kms:v2:dek-secret-encryption`: Cifragem AES-256-GCM dos segredos e chaves privadas Ed25519 (nonce CSPRNG de 96 bits + AAD `v2:secret:<keyId>` / `v2:ed25519-priv:<keyId>`).
   - `winhood:kms:v2:store-metadata-integrity`: Autenticação de integridade estrutural vinculada à KEK (`kekBoundIntegrityMacHex`).
   - `winhood:kms:v2:trust-store-integrity`: Autenticação independente do arquivo externo `trust-store.json`.

---

## 3. Trust Store Ed25519 Fisicamente Separado e Limitações de Rollback

1. **Trust Store Separado (`trust-store.json`):**
   - As chaves públicas Ed25519 confiáveis (`ACTIVE`, `ROTATED_VERIFY_ONLY`, `REVOKED`) e o fingerprint âncora raiz (`rootAnchorFingerprintSha256`) são persistidos em `trust-store.json` separado de `keystore.json` (`trustStoreSeparated: true`), autenticado por chave derivada da KEK.
2. **Limitações Arquiteturais Declaradas contra Rollback Local:**
   - O contador monotônico (`monotonicSequence` + arquivo `.seq`) e o MAC vinculado à KEK detectam corrupção parcial ou restauração desalinhada entre `keystore.json`, `.seq` e `trust-store.json`.
   - **Limitação real:** Como não há TPM 2.0 nem serviço remoto de transparência (`hardwareTpmOrRemoteAnchorAvailable: false`), um atacante com acesso privilegiado de escrita ao sistema de arquivos local pode fazer snapshot e restaurar **simultaneamente** todos os arquivos locais (`keystore.json`, `.seq`, `trust-store.json`) para um estado anterior válido. Proteção absoluta contra rollback físico exige âncora em hardware (TPM NV Index) ou log remoto imutável.
