import type { NormalizedFinding } from '../types/benchmark';

export type ComplianceFrameworkKey =
  | 'OWASP_TOP_10_2021'
  | 'CWE_TOP_25'
  | 'PCI_DSS_V4'
  | 'ISO_27001_2022';

export interface ComplianceControlMappingEntry {
  framework: ComplianceFrameworkKey;
  controlId: string;
  controlTitle: string;
  status: 'FINDINGS_DETECTED' | 'NO_FINDINGS_IN_ANALYZED_SCOPE';
  findingsCount: number;
  criticalOrBlockerCount: number;
  matchedCwes: string[];
  evidenceFindingIds: string[];
}

export interface ComplianceTraceabilityMatrix {
  generatedAt: string;
  runId: string;
  disclaimer: string;
  scopeNotes: string[];
  totalFindingsMapped: number;
  byFramework: Record<ComplianceFrameworkKey, ComplianceControlMappingEntry[]>;
}

interface ControlDescriptor {
  framework: ComplianceFrameworkKey;
  controlId: string;
  controlTitle: string;
  cwes: string[];
  categories?: NormalizedFinding['category'][];
}

const TRACEABILITY_CATALOG: ControlDescriptor[] = [
  // OWASP Top 10:2021
  {
    framework: 'OWASP_TOP_10_2021',
    controlId: 'A01:2021',
    controlTitle: 'Broken Access Control (incl. Path Traversal)',
    cwes: ['CWE-22', 'CWE-284', 'CWE-200', 'CWE-639', 'CWE-862'],
  },
  {
    framework: 'OWASP_TOP_10_2021',
    controlId: 'A02:2021',
    controlTitle: 'Cryptographic Failures',
    cwes: ['CWE-328', 'CWE-338', 'CWE-311', 'CWE-256', 'CWE-327', 'CWE-916'],
  },
  {
    framework: 'OWASP_TOP_10_2021',
    controlId: 'A03:2021',
    controlTitle: 'Injection (SQLi, Command Injection, Code Injection, XSS)',
    cwes: ['CWE-89', 'CWE-78', 'CWE-95', 'CWE-94', 'CWE-79'],
  },
  {
    framework: 'OWASP_TOP_10_2021',
    controlId: 'A05:2021',
    controlTitle: 'Security Misconfiguration (incl. IaC / Container Privileges)',
    cwes: ['CWE-250', 'CWE-284', 'CWE-16'],
    categories: ['IAC'],
  },
  {
    framework: 'OWASP_TOP_10_2021',
    controlId: 'A06:2021',
    controlTitle: 'Vulnerable and Outdated Components (SCA / SBOM)',
    cwes: ['CWE-1395', 'CWE-1104', 'CWE-502'],
    categories: ['SCA'],
  },
  {
    framework: 'OWASP_TOP_10_2021',
    controlId: 'A07:2021',
    controlTitle: 'Identification and Authentication Failures (incl. Hardcoded Secrets)',
    cwes: ['CWE-798', 'CWE-259', 'CWE-347', 'CWE-287'],
    categories: ['SECRETS'],
  },
  {
    framework: 'OWASP_TOP_10_2021',
    controlId: 'A08:2021',
    controlTitle: 'Software and Data Integrity Failures (CI/CD & Deserialization)',
    cwes: ['CWE-502', 'CWE-94'],
  },
  {
    framework: 'OWASP_TOP_10_2021',
    controlId: 'A09:2021',
    controlTitle: 'Security Logging and Monitoring Failures',
    cwes: ['CWE-390', 'CWE-778'],
  },
  {
    framework: 'OWASP_TOP_10_2021',
    controlId: 'A10:2021',
    controlTitle: 'Server-Side Request Forgery (SSRF)',
    cwes: ['CWE-918'],
  },

  // CWE Top 25 Most Dangerous Software Weaknesses
  { framework: 'CWE_TOP_25', controlId: 'CWE-79', controlTitle: 'Improper Neutralization of Input During Web Page Generation (XSS)', cwes: ['CWE-79'] },
  { framework: 'CWE_TOP_25', controlId: 'CWE-89', controlTitle: 'SQL Injection', cwes: ['CWE-89'] },
  { framework: 'CWE_TOP_25', controlId: 'CWE-22', controlTitle: 'Path Traversal', cwes: ['CWE-22'] },
  { framework: 'CWE_TOP_25', controlId: 'CWE-78', controlTitle: 'OS Command Injection', cwes: ['CWE-78'] },
  { framework: 'CWE_TOP_25', controlId: 'CWE-94', controlTitle: 'Improper Control of Generation of Code (Code Injection)', cwes: ['CWE-94', 'CWE-95'] },
  { framework: 'CWE_TOP_25', controlId: 'CWE-798', controlTitle: 'Use of Hard-coded Credentials', cwes: ['CWE-798'] },
  { framework: 'CWE_TOP_25', controlId: 'CWE-502', controlTitle: 'Deserialization of Untrusted Data', cwes: ['CWE-502'] },
  { framework: 'CWE_TOP_25', controlId: 'CWE-918', controlTitle: 'Server-Side Request Forgery (SSRF)', cwes: ['CWE-918'] },
  { framework: 'CWE_TOP_25', controlId: 'CWE-250', controlTitle: 'Execution with Unnecessary Privileges', cwes: ['CWE-250'] },

  // PCI DSS v4.0 (Technical engineering traceability only)
  {
    framework: 'PCI_DSS_V4',
    controlId: 'PCI-Req-3.5',
    controlTitle: 'Req 3.5: Proteção de dados e algoritmos criptográficos fortes',
    cwes: ['CWE-328', 'CWE-338', 'CWE-311', 'CWE-256'],
  },
  {
    framework: 'PCI_DSS_V4',
    controlId: 'PCI-Req-6.2.4',
    controlTitle: 'Req 6.2.4: Prevenção de ataques comuns (Injection, XSS, Path Traversal, SSRF)',
    cwes: ['CWE-89', 'CWE-78', 'CWE-94', 'CWE-95', 'CWE-79', 'CWE-22', 'CWE-918'],
  },
  {
    framework: 'PCI_DSS_V4',
    controlId: 'PCI-Req-6.3.2',
    controlTitle: 'Req 6.3.2: Inventário de software e componentes terceiros (SBOM / SCA)',
    cwes: ['CWE-1395', 'CWE-1104'],
    categories: ['SCA'],
  },
  {
    framework: 'PCI_DSS_V4',
    controlId: 'PCI-Req-8.3',
    controlTitle: 'Req 8.3: Gestão forte de credenciais e proibição de segredos hardcoded',
    cwes: ['CWE-798', 'CWE-259', 'CWE-347'],
    categories: ['SECRETS'],
  },

  // ISO/IEC 27001:2022 Annex A (Technical engineering traceability only)
  {
    framework: 'ISO_27001_2022',
    controlId: 'ISO-A.8.8',
    controlTitle: 'A.8.8: Gestão de vulnerabilidades técnicas',
    cwes: ['CWE-1395', 'CWE-1104', 'CWE-502'],
    categories: ['SCA'],
  },
  {
    framework: 'ISO_27001_2022',
    controlId: 'ISO-A.8.24',
    controlTitle: 'A.8.24: Uso de criptografia',
    cwes: ['CWE-328', 'CWE-338', 'CWE-311', 'CWE-256', 'CWE-916'],
  },
  {
    framework: 'ISO_27001_2022',
    controlId: 'ISO-A.8.25',
    controlTitle: 'A.8.25 / A.8.28: Ciclo de vida e codificação segura',
    cwes: ['CWE-89', 'CWE-78', 'CWE-94', 'CWE-95', 'CWE-79', 'CWE-22', 'CWE-918', 'CWE-390'],
  },
  {
    framework: 'ISO_27001_2022',
    controlId: 'ISO-A.5.17',
    controlTitle: 'A.5.17: Informações de autenticação e proteção de segredos',
    cwes: ['CWE-798', 'CWE-259'],
    categories: ['SECRETS'],
  },
];

export class ComplianceMapper {
  public static buildTraceabilityMatrix(params: {
    runId: string;
    findings: NormalizedFinding[];
    deterministicTimestamp?: string;
  }): ComplianceTraceabilityMatrix {
    const activeFindings = params.findings.filter((f) => {
      const st = f.lifecycleState || f.validationStatus;
      return (
        st !== 'FALSE_POSITIVE' &&
        st !== 'FALSE_POSITIVE_REVIEWED' &&
        st !== 'VERIFIED_RESOLVED' &&
        st !== 'NOT_REPRODUCIBLE'
      );
    });

    const byFramework: Record<ComplianceFrameworkKey, ComplianceControlMappingEntry[]> = {
      OWASP_TOP_10_2021: [],
      CWE_TOP_25: [],
      PCI_DSS_V4: [],
      ISO_27001_2022: [],
    };

    const mappedFindingIds = new Set<string>();

    for (const ctrl of TRACEABILITY_CATALOG) {
      const matched = activeFindings.filter((f) => {
        const cweMatch = Boolean(f.cwe && ctrl.cwes.includes(f.cwe));
        const catMatch = Boolean(ctrl.categories && ctrl.categories.includes(f.category));
        return cweMatch || catMatch;
      });
      for (const f of matched) {
        mappedFindingIds.add(f.id);
      }

      const criticalOrBlockerCount = matched.filter(
        (f) => f.severity === 'BLOCKER' || f.severity === 'CRITICAL'
      ).length;

      byFramework[ctrl.framework].push({
        framework: ctrl.framework,
        controlId: ctrl.controlId,
        controlTitle: ctrl.controlTitle,
        status: matched.length > 0 ? 'FINDINGS_DETECTED' : 'NO_FINDINGS_IN_ANALYZED_SCOPE',
        findingsCount: matched.length,
        criticalOrBlockerCount,
        matchedCwes: Array.from(new Set(matched.map((m) => m.cwe).filter((c): c is string => Boolean(c)))).sort(),
        evidenceFindingIds: matched.map((m) => m.id),
      });
    }

    return {
      generatedAt: params.deterministicTimestamp || new Date().toISOString(),
      runId: params.runId,
      disclaimer:
        'TRACEABILITY_ONLY_NOT_CERTIFICATION: Este mapeamento associa achados técnicos aos controles aplicáveis de OWASP Top 10, CWE Top 25, PCI DSS v4.0 e ISO/IEC 27001:2022 apenas para rastreabilidade de engenharia e auditoria. Não representa nem substitui certificação ou auditoria formal.',
      scopeNotes: [
        'Ausência de achados em um controle indica apenas ausência de detecção no escopo estático/SCA/IaC analisado — não equivale a conformidade integral organizacional.',
        'Controles físicos, organizacionais e processuais fora do código-fonte não são mensurados pelo WinHood.',
      ],
      totalFindingsMapped: mappedFindingIds.size,
      byFramework,
    };
  }
}
