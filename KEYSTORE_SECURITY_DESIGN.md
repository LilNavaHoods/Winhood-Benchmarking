# Especificação da Arquitetura Criptográfica do Keystore (`KEYSTORE_SECURITY_DESIGN.md`)

**Versão do Formato:** `WINHOOD-ENVELOPE-V2`  
**Implementação Principal:** `src/security/KeyManagementService.ts` e `src/engine/evidenceProvenanceEngine.ts`

---

## 1. Visão Geral da Criptografia por Envelope (Envelope Encryption)

O `KeyManagementService` substitui chaves derivadas de atributos previsíveis da máquina por uma arquitetura formal de **Criptografia por Envelope**:

1. **DEK (Data Encryption Key):**
   - Gerada via CSPRNG (`crypto.randomBytes(32)` — 256 bits de entropia pura), sem qualquer dependência de `hostname`, `username` ou identificadores estáticos de hardware.
2. **Proteção da DEK pela KEK (Key Encryption Key):**
   - A DEK nunca é persistida em texto claro. Ela é cifrada com `AES-256-GCM` (nonce CSPRNG de 96 bits + AAD vinculando versão do envelope e modo operacional) sob uma `KEK_WRAP` derivada via **HKDF-SHA256 (RFC 5869)**.
   - Fontes de material de chave mestre (IKM) para a KEK, em ordem de precedência:
     - **Windows DPAPI (`DPAPI_PROTECTED`):** Quando em Windows (`win32`), o blob de entropia mestre de 256 bits é protegido por `System.Security.Cryptography.ProtectedData::Protect(..., CurrentUser)` em `.keystore.dpapi.bin`.
     - **Segredo Externo Explícito (`EXTERNAL_SECRET_HKDF`):** Quando configurado via variável de ambiente `WINHOOD_MASTER_KEY_SECRET` (mínimo de 16 caracteres) em pipelines CI/CD ou servidores dedicados.
     - **Chave Local Persistida com Permissão Restrita (`OS_KEYRING_OR_LOCAL_KEK`):** Em ambientes Linux/macOS locais, um arquivo de entropia CSPRNG de 256 bits (`.keystore.kek.bin`) é gerado com permissão `0600` (somente leitura/escrita pelo proprietário do processo).

---

## 2. Segregação de Chaves por Finalidade via HKDF (RFC 5869)

É proibido reutilizar a mesma chave criptográfica para cifragem, autenticação e proteção de integridade. A partir da DEK e do IKM mestre, o método `deriveHkdfPurposeKey(ikm, saltHex, purposeInfo)` deriva subchaves independentes de 256 bits usando contextos `info` distintos:

- `winhood:kms:v2:kek-wrap`: Exclusiva para cifrar/decifrar o envelope da DEK com AES-256-GCM.
- `winhood:kms:v2:dek-secret-encryption`: Exclusiva para cifrar segredos individuais do cofre (`evidenceSecrets`, chaves privadas Ed25519 e credenciais de conectores) com AES-256-GCM.
- `winhood:kms:v2:store-metadata-integrity`: Exclusiva para assinar o cabeçalho estrutural e o contador monotônico do cofre.

---

## 3. Autenticação AES-256-GCM e Ausência de HMAC Redundante

- Cada segredo armazenado no cofre utiliza `encryptWithAes256GcmEnvelope(plaintext, subKey, aadContext)`:
  - Algoritmo: `aes-256-gcm`
  - Nonce (IV): 12 bytes (96 bits) gerados exclusivamente via `crypto.randomBytes(12)` a cada operação.
  - AAD (Additional Authenticated Data): vincula `keyId`, finalidade e versão do formato (`v2:secret:<keyId>` ou `v2:ed25519-priv:<keyId>`).
  - Tag de Autenticação GCM: 16 bytes (128 bits) validados obrigatoriamente antes de disponibilizar qualquer byte decifrado.
- Não se utiliza HMAC genérico como substituto da autenticação nativa do modo Galois/Counter (GCM).

---

## 4. Proteção contra Rollback e Corrupção

- O arquivo do cofre inclui o contador monotônico `monotonicSequence`, incrementado a cada mutação (criação, rotação de chave, revogação ou gravação de segredo) e espelhado no arquivo auxiliar `.seq` com permissão `0600`.
- Na leitura, se `store.monotonicSequence < persistedFloorSeq`, o cofre sinaliza violação de rollback (`rollbackProtectionVerified = false`).
- Em modo `PRODUCTION_SECURE`, qualquer adulteração de tag GCM, violação de AAD ou corrupção estrutural falha de forma fechada (*fail-closed*), bloqueando o uso de dados corrompidos.

---

## 5. Trust Store Ed25519 e Ciclo de Vida de Chaves

- O cofre mantém o registro `trustedPublicKeys` contendo chaves públicas Ed25519 autorizadas (`keyId`, `publicKeyPem`, `fingerprintSha256`, `status`: `ACTIVE` | `ROTATED_RETIRED` | `REVOKED`, `createdAt`, `rotatedAt`, `revokedAt`).
- Durante `verifyEvidenceChainAndManifest()`, o motor de proveniência não confia cegamente na chave pública embutida no manifesto recebido: ele consulta `KeyManagementService.verifyTrustedEd25519PublicKey(keyId, publicKeyPem, signedAt)` para garantir que:
  1. O `keyId` existe no Trust Store;
  2. O `fingerprintSha256` da chave pública coincide exatamente com o registro confiável;
  3. A chave não foi revogada (`REVOKED`);
  4. A assinatura foi gerada dentro da janela de validade da chave.
