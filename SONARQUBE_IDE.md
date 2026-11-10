# SONARQUBE_IDE.md — Integração Opcional com SonarQube for VS Code (Connected Mode)

## 1. Documentação Oficial
- https://docs.sonarsource.com/sonarqube-for-vs-code/

## 2. Papel da Extensão no Ecossistema
- A extensão **SonarQube for VS Code** (`SonarSource.sonarlint-vscode` no Visual Studio Marketplace) é uma ferramenta de feedback em tempo real na IDE para desenvolvedores.
- Ela **não é requisito** para a execução de benchmarks pelo backend do WinHood Analyzer.
- A plataforma **nunca baixa ou instala extensões automaticamente** no ambiente do usuário sem consentimento explícito.

## 3. Configuração do Connected Mode
Através do cartão **03. SonarQube for VS Code** na tela **Ferramentas e Integrações**, o desenvolvedor pode gerar mediante autorização o arquivo `.vscode/settings.json` para conectar sua IDE a:
- **SonarQube Community Build** (`http://localhost:9000` ou servidor remoto)
- **SonarQube Server**
- **SonarQube Cloud** (`https://sonarcloud.io`)

Exemplo gerado para sincronizar o perfil de qualidade (`Sonar way`) e o conjunto de regras entre o servidor e a IDE:
```json
{
  "sonarlint.connectedMode.connections.sonarqube": [
    {
      "connectionId": "winhood-sonarqube-cb",
      "serverUrl": "http://localhost:9000"
    }
  ],
  "sonarlint.connectedMode.project": {
    "connectionId": "winhood-sonarqube-cb",
    "projectKey": "winhood-software-a-vaultcore-internal"
  }
}
```
