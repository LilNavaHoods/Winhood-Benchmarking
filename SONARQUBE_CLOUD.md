# SONARQUBE_CLOUD.md — Adaptador Opcional para SonarQube Cloud (SaaS)

## 1. Documentação Oficial
- https://docs.sonarsource.com/sonarqube-cloud

## 2. Natureza do Serviço e Privacidade do Código-Fonte
- O **SonarQube Cloud** (`https://sonarcloud.io`) é um serviço SaaS gerenciado pela SonarSource.
- A plataforma **nunca tenta baixar ou instalar** o SonarQube Cloud localmente.
- **Consentimento Explícito Obrigatório:** Nenhum código-fonte ou metadado de projeto privado do usuário é enviado para o SonarQube Cloud sem que o usuário marque explicitamente a autorização na aba **Ferramentas e Integrações -> 02. SonarQube Cloud** e configure a chave da organização (`organizationKey`) e o token Bearer.

## 3. Operações Suportadas
Quando autorizado e configurado (`READY`), o adaptador permite:
1. Validar a autenticação e a organização na nuvem;
2. Importar métricas, issues e resultados de Quality Gate de projetos autorizados na organização;
3. Comparar os resultados de projetos hospedados no SonarQube Cloud sob a mesma estrutura de avaliação A/B do Benchmark Analyzer.
