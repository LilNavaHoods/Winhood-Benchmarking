import type {
  GitarConnectionState,
  GitarIntegrationRecord,
  GitProviderType,
} from '../../types/benchmark';
import { SonarQubeConnection } from '../sonarqube/SonarQubeConnection';

/**
 * GitarConnection (Seção 9, 9.2 e 9.3)
 * Gerencia credenciais, consentimento explícito para envio de código e políticas de segurança
 * (proibição de escrita direta nos arquivos originais, branch isolada, aprovação humana obrigatória).
 */
export class GitarConnection {
  private encryptedToken: string | null = null;

  public setToken(plainToken?: string): void {
    if (!plainToken || plainToken.trim().length === 0) {
      this.encryptedToken = null;
      return;
    }
    this.encryptedToken = SonarQubeConnection.encryptToken(plainToken.trim());
  }

  public getToken(): string | null {
    if (!this.encryptedToken) return null;
    return SonarQubeConnection.decryptToken(this.encryptedToken);
  }

  public static validateSafetyPolicies(
    record: GitarIntegrationRecord
  ): { valid: boolean; violations: string[] } {
    const violations: string[] = [];
    if (record.safetyPolicies.allowDirectModificationOfOriginalFiles !== false) {
      violations.push(
        'VIOLAÇÃO DE SEGURANÇA: O Gitar não pode modificar diretamente os arquivos originais dos softwares A e B.'
      );
    }
    if (record.safetyPolicies.requireHumanApprovalBeforeApply !== true) {
      violations.push(
        'VIOLAÇÃO DE SEGURANÇA: Aprovação humana explícita é obrigatória antes de aplicar correções.'
      );
    }
    return {
      valid: violations.length === 0,
      violations,
    };
  }

  public static buildNotConfiguredState(
    gitProvider: GitProviderType = 'GITHUB'
  ): {
    connectionState: GitarConnectionState;
    message: string;
  } {
    return {
      connectionState: 'NOT_CONFIGURED',
      message: `Integração Gitar AI (${gitProvider}) está em estado NOT_CONFIGURED. Conforme a Seção 9.2, nenhuma revisão de IA é simulada quando a conta não está conectada.`,
    };
  }
}
