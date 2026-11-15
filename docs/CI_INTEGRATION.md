# Integração de CI/CD, Códigos de Saída Canônicos e Webhooks Assinados (`docs/CI_INTEGRATION.md`)

Este documento especifica os contratos oficiais de automação do **WinHood Benchmarking** para pipelines de Integração Contínua (**GitHub Actions**, **GitLab CI**, **Jenkins**) e receptores de **Webhooks Assinados (`HMAC-SHA256`)**.

---

## 1. Tabela Canônica de Exit Codes (`--ci-exit-codes`)

Ao executar a CLI em pipelines de CI/CD com a flag `--ci-exit-codes` (ou variável de ambiente `WINHOOD_CI_CANONICAL_EXIT_CODES=1`), o WinHood emite os seguintes códigos de saída canônicos:

| Exit Code Canônico | Estado do Quality Gate (`decision`) | Comportamento Recomendado no Pipeline |
| :---: | :--- | :--- |
| **`0`** | `APPROVED` | **Aprovar Merge / prosseguir deploy.** Todas as condições do gate foram satisfeitas. |
| **`1`** | `APPROVED_WITH_RESERVATIONS` | **Aprovar com aviso (Warning / Unstable)** ou bloquear caso `fail-on: APPROVED_WITH_RESERVATIONS`. |
| **`2`** | `BLOCKED` / `REJECTED` | **Bloquear Merge / abortar pipeline imediatamente.** Falha em condição bloqueante de segurança, licença ou qualidade. |
| **`3`** | `INCONCLUSIVE` | **Requer revisão manual.** Cobertura de escopo (`< 50%`) ou Confiança da Evidência insuficiente para aprovação automática. |
| **`4`** | `EXECUTION_ERROR` | **Falha técnica de execução** (caminho inexistente, JSON/SARIF malformado ou parâmetro inválido). |

*(Nota de retrocompatibilidade: sem `--ci-exit-codes`, a CLI preserva o mapeamento clássico `0 = APPROVED/APPROVED_WITH_RESERVATIONS`, `1 = BLOCKED/REJECTED`, `2 = INCONCLUSIVE`, `3 = ERROR` para não quebrar scripts existentes).*

---

## 2. GitHub Action Oficial (`integrations/github-action/action.yml`)

### Inputs, Outputs e Permissões Mínimas

- **Permissões mínimas necessárias no workflow:**
  - `contents: read`
  - `security-events: write` (para publicação nativa do SARIF 2.1.0 na aba Security via `github/codeql-action/upload-sarif`)
  - `pull-requests: write` (para PR decoration automática com resumo, delta de achados e decisão do gate)
- **Inputs:**
  - `gate`: ID do Quality Gate versionado (padrão: `winhood-standard-v2`)
  - `profile`: Perfil de análise (padrão: `mqr-strict`)
  - `fail-on`: Estado mínimo para reprovação do workflow (`BLOCKED`, `APPROVED_WITH_RESERVATIONS`, `INCONCLUSIVE`)
  - `path`: Caminho do diretório a auditar (padrão: `.`)
  - `sarif-output`: Caminho do relatório SARIF 2.1.0 gerado (padrão: `winhood-results.sarif`)
- **Outputs:**
  - `decision`: Decisão resultante do gate (`APPROVED`, `APPROVED_WITH_RESERVATIONS`, `BLOCKED`, `INCONCLUSIVE`, `REJECTED`)
  - `exit-code`: Código de saída canônico (`0..4`)
  - `report-path`: Caminho absoluto do arquivo SARIF gerado

Veja o exemplo completo em [`examples/github-workflow.yml`](../examples/github-workflow.yml).

---

## 3. GitLab CI Component Oficial (`templates/winhood.gitlab-ci.yml`)

O componente oficial `templates/winhood.gitlab-ci.yml` utiliza `spec: inputs:` (`gate`, `profile`, `fail_on`) e define `rules` estritas (`allow_failure: false`) para bloquear Merge Requests quando o gate retornar `BLOCKED` (exit code `2`).

Veja o exemplo funcional em [`examples/.gitlab-ci.yml`](../examples/.gitlab-ci.yml).

---

## 4. Jenkins Shared Library (`winhoodAnalyze()` e `winhoodGate()`)

Disponível em `integrations/jenkins/vars/`:
- `winhoodAnalyze(path: '.', profile: 'mqr-strict', gate: 'winhood-standard-v2', format: 'sarif')`: Executa a auditoria determinística e arquiva o relatório assinado.
- `winhoodGate(path: '.', gate: 'winhood-standard-v2', failOn: 'BLOCKED')`: Avalia o gate com `--ci-exit-codes` e interrompe a pipeline com `error(...)` quando `BLOCKED` (`exitCode == 2`).

Veja o exemplo funcional em [`examples/Jenkinsfile`](../examples/Jenkinsfile).

---

## 5. Validação de Webhook Assinado (`HMAC-SHA256`)

Todo webhook disparado pelo WinHood inclui o cabeçalho `X-WinHood-Signature` no formato:
`t=<unix_timestamp>,v1=<hex_hmac_sha256>`

O HMAC-SHA256 é calculado sobre a string `${timestamp}.${rawBody}` usando o segredo compartilhado do webhook.

### 5.1 Exemplo de Validação em Node.js

```javascript
import crypto from 'node:crypto';

export function verifyWinHoodWebhook(rawBody, signatureHeader, secret, toleranceSec = 300) {
  const parts = Object.fromEntries(
    signatureHeader.split(',').map((kv) => kv.trim().split('='))
  );
  const timestamp = Number(parts.t);
  const v1 = parts.v1;
  if (!timestamp || !v1) return false;

  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - timestamp) > toleranceSec) return false;

  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${rawBody}`, 'utf8')
    .digest('hex');

  return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(v1, 'hex'));
}
```

### 5.2 Exemplo de Validação em Python

```python
import hashlib
import hmac
import time

def verify_winhood_webhook(raw_body: str, signature_header: str, secret: str, tolerance_sec: int = 300) -> bool:
    parts = dict(item.strip().split("=", 1) for item in signature_header.split(",") if "=" in item)
    timestamp_str = parts.get("t")
    v1_sig = parts.get("v1")
    if not timestamp_str or not v1_sig:
        return False

    timestamp = int(timestamp_str)
    if abs(int(time.time()) - timestamp) > tolerance_sec:
        return False

    signed_payload = f"{timestamp}.{raw_body}".encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1_sig)
```

### 5.3 Exemplo de Validação em Go

```go
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func VerifyWinHoodWebhook(rawBody string, signatureHeader string, secret string, toleranceSec int64) bool {
	var tsStr, v1Hex string
	for _, part := range strings.Split(signatureHeader, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			if kv[0] == "t" {
				tsStr = kv[1]
			} else if kv[0] == "v1" {
				v1Hex = kv[1]
			}
		}
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil || v1Hex == "" {
		return false
	}
	now := time.Now().Unix()
	if now-ts > toleranceSec || ts-now > toleranceSec {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%d.%s", ts, rawBody)))
	expected := mac.Sum(nil)
	received, err := hex.DecodeString(v1Hex)
	if err != nil {
		return false
	}
	return hmac.Equal(expected, received)
}
```
