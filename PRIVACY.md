# Política de Privacidade e Transparência de IA — WinHood Benchmark Analyzer

**Última atualização:** 16 de novembro de 2026  
**Versão do Produto:** 4.4.0  
**Publicador:** WinHood Engineering & AppSec (`io.winhood.benchmark.analyzer`)  
**Repositório Oficial:** https://github.com/LilNavaHoods/Winhood-Benchmarking  
**Canal de Suporte, Relatórios e Reclamações:** https://github.com/LilNavaHoods/Winhood-Benchmarking/issues

---

## 1. Execução 100% Local e Soberania de Dados

O **WinHood Benchmark Analyzer** é uma ferramenta desktop e web local de código aberto (licença MIT) projetada sob o princípio de **Privacidade por Design (Privacy by Design)** e **Execução 100% Local**:

- **Armazenamento Exclusivamente Local:** Todos os projetos, códigos-fonte analisados, relatórios SARIF/HTML/JSON/PDF, trilhas de auditoria e configurações permanecem armazenados exclusivamente na máquina do próprio usuário (`%APPDATA%\WinHood` ou `%LOCALAPPDATA%\WinHoodBenchmarking` no Windows, ou `.winhood_data` no modo local).
- **Criptografia em Repouso (`whdb:enc:v2`):** O banco de dados local e os segredos de integração são protegidos em repouso utilizando criptografia autenticada **AES-256-GCM** com chaves gerenciadas pelo cofre local (`KeyManagementService`).
- **Credenciais de Acesso Locais:** Senhas e PINs rápidos são processados localmente com derivação criptográfica **scrypt** (`N=16384, r=8, p=1` + salt aleatório de 16 bytes). Credenciais **Windows Hello (WebAuthn / FIDO2)** armazenam apenas a chave pública criptográfica (`ES256` / `RS256`) e o contador anti-replay localmente; dados biométricos jamais saem do TPM/Windows Hello do sistema operacional.
- **Zero Telemetria Externa:** O aplicativo não coleta dados pessoais, não utiliza rastreadores analíticos de terceiros e não exibe anúncios.

---

## 2. Uso de Cookies Técnicos (`HttpOnly`)

Para proteger a comunicação entre a interface local (`http://localhost`) e o motor de análise local (`127.0.0.1`), o WinHood utiliza exclusivamente cookies estritamente técnicos e funcionais:

| Nome do Cookie | Finalidade Técnica | Escopo e Retenção |
| :--- | :--- | :--- |
| `winhood_session` | Identificador criptográfico de sessão autenticada (`HttpOnly`, `SameSite=Strict`). | Local (`localhost`), revogado no logout ou após expiração. |
| `winhood_csrf` | Token de proteção contra falsificação de requisições (`CSRF Double-Submit`). | Local (`localhost`), vinculado à sessão ativa. |

Nenhum cookie é utilizado para perfilamento, publicidade ou rastreamento entre sites.

---

## 3. Transparência sobre Inteligência Artificial e Serviços Externos

O motor principal de benchmark, análise estática (SAST, Taint Analysis, SCA, SBOM, Segredos e Arquitetura) e cálculo de pontuação MQR do WinHood funciona **100% offline e localmente**.

O envio de fragmentos de código, metadados de repositórios ou métricas para serviços externos ocorre **exclusivamente quando o próprio usuário configura voluntariamente suas credenciais e aciona a integração**:

1. **Google Gemini API (`@google/genai`):** Utilizada apenas se o usuário configurar explicitamente sua chave `GEMINI_API_KEY` no ambiente local e acionar recursos assistidos. Nenhum código é enviado sem ação explícita do usuário.
2. **SonarQube Cloud / SonarQube Server (`MqrBridge`):** Utilizado apenas quando o usuário cadastra seu token Bearer e URL/organização para sincronizar Quality Gates ou exportar relatórios SARIF.
3. **GitHub API / Gitar AI Remediation:** Utilizada apenas quando o usuário pesquisa/importa repositórios do GitHub ou aciona revisões supervisionadas com seu próprio token.

O WinHood valida todos os destinos de rede com proteção anti-SSRF (`SsrfGuard`) para impedir conexões não autorizadas a redes internas ou serviços de metadata.

---

## 4. Direito de Acesso, Portabilidade e Exclusão de Dados Locais

O usuário possui controle integral sobre seus dados:

- **Exportação e Portabilidade:** Todos os relatórios e evidências podem ser exportados a qualquer momento nos formatos abertos JSON, Markdown, HTML/PDF e SARIF 2.1.0.
- **Exclusão de Conta Local (`DELETE /api/auth/me`):** O usuário pode excluir sua própria conta e revogar todas as sessões diretamente na interface do aplicativo (menu lateral **Excluir minha conta**), removendo imediatamente seu registro de `auth_users.json`.
- **Remoção Completa:** A desinstalação ou limpeza do diretório de dados do usuário remove permanentemente todos os bancos locais e chaves criptográficas associadas.

---

## 5. Contato de Suporte, Relatórios e Reclamações

Para dúvidas sobre privacidade, solicitações de suporte técnico, envio de relatórios ou reclamações, utilize exclusivamente o canal oficial do projeto no GitHub:
- **Publicador:** WinHood Engineering & AppSec
- **Repositório Oficial:** https://github.com/LilNavaHoods/Winhood-Benchmarking
- **Suporte, Relatórios e Reclamações (GitHub Issues):** https://github.com/LilNavaHoods/Winhood-Benchmarking/issues
