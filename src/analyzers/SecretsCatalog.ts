import crypto from 'node:crypto';
import type { SeverityLevel } from '../types/benchmark';
import type { AstIssueCandidate } from './types';

export const SECRETS_CATALOG_VERSION = '2026.11.0';

export interface SecretPatternDefinition {
  patternId: string;
  ruleId: string;
  name: string;
  version: string;
  severity: SeverityLevel;
  cwe: string;
  owaspTop10: string;
  cvssBase: number;
  regexSource: string;
  regexFlags: string;
  minShannonEntropy: number;
  requiresContextHint: boolean;
  supportsOptionalValidation: boolean;
  validationMethod: 'FORMAT_CHECKSUM_ONLY' | 'OPT_IN_PROVIDER_PING' | 'NONE';
  falsePositiveExclusions: string[];
  remediation: string;
}

export const SECRETS_PATTERN_CATALOG: SecretPatternDefinition[] = [
  {
    patternId: 'sec-aws-access-key',
    ruleId: 'sec:S6418-AWS',
    name: 'AWS Access Key ID (AKIA/ASIA)',
    version: '1.2.0',
    severity: 'BLOCKER',
    cwe: 'CWE-798',
    owaspTop10: 'A07:2021',
    cvssBase: 9.8,
    regexSource: '\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b',
    regexFlags: 'g',
    minShannonEntropy: 3.0,
    requiresContextHint: false,
    supportsOptionalValidation: true,
    validationMethod: 'FORMAT_CHECKSUM_ONLY',
    falsePositiveExclusions: ['AKIAIOSFODNN7EXAMPLE', 'AKIA0000000000000000', 'test fixtures'],
    remediation: 'Revogue a credencial no IAM e utilize STS/IAM Roles temporários ou KMS.',
  },
  {
    patternId: 'sec-github-pat',
    ruleId: 'sec:S6418-GH',
    name: 'GitHub Personal / Fine-Grained Token',
    version: '1.1.0',
    severity: 'BLOCKER',
    cwe: 'CWE-798',
    owaspTop10: 'A07:2021',
    cvssBase: 9.4,
    regexSource: '\\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\\b',
    regexFlags: 'g',
    minShannonEntropy: 3.4,
    requiresContextHint: false,
    supportsOptionalValidation: true,
    validationMethod: 'OPT_IN_PROVIDER_PING',
    falsePositiveExclusions: ['ghp_000000000000000000000000000000000000', 'example_token'],
    remediation: 'Revogue o token no GitHub Settings e mova para GitHub Actions Secrets ou Vault.',
  },
  {
    patternId: 'sec-private-key-pem',
    ruleId: 'sec:S6418-PEM',
    name: 'Private Key PEM Block (RSA/EC/OPENSSH)',
    version: '1.0.0',
    severity: 'BLOCKER',
    cwe: 'CWE-321',
    owaspTop10: 'A02:2021',
    cvssBase: 9.8,
    regexSource: '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----',
    regexFlags: 'g',
    minShannonEntropy: 2.5,
    requiresContextHint: false,
    supportsOptionalValidation: true,
    validationMethod: 'FORMAT_CHECKSUM_ONLY',
    falsePositiveExclusions: ['unit-test synthetic fixtures when clearly annotated as mock/dummy'],
    remediation: 'Nunca versionar chaves privadas no repositório; utilizar HSM, DPAPI ou KMS.',
  },
  {
    patternId: 'sec-jwt-bearer-literal',
    ruleId: 'sec:S6418-JWT',
    name: 'Hardcoded Signed JWT Token',
    version: '1.0.0',
    severity: 'CRITICAL',
    cwe: 'CWE-798',
    owaspTop10: 'A07:2021',
    cvssBase: 8.6,
    regexSource: '\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{12,}\\b',
    regexFlags: 'g',
    minShannonEntropy: 3.8,
    requiresContextHint: false,
    supportsOptionalValidation: true,
    validationMethod: 'FORMAT_CHECKSUM_ONLY',
    falsePositiveExclusions: ['documentation snippets containing dummy/example payloads'],
    remediation: 'Remover tokens JWT literais e emitir tokens curtos em runtime.',
  },
  {
    patternId: 'sec-generic-high-entropy-secret',
    ruleId: 'sec:S6418-ENTROPY',
    name: 'High-Entropy Credential / API Secret Assignment',
    version: '1.3.0',
    severity: 'BLOCKER',
    cwe: 'CWE-798',
    owaspTop10: 'A07:2021',
    cvssBase: 9.1,
    regexSource: '(?:api[_-]?(?:key|secret)|secret[_-]?key|client[_-]?secret|master[_-]?key|private[_-]?token|db[_-]?password|jwt[_-]?secret|signing[_-]?key)\\s*[:=]\\s*[\'"`]([^\'"`\\n]{14,})[\'"`]',
    regexFlags: 'gi',
    minShannonEntropy: 3.3,
    requiresContextHint: true,
    supportsOptionalValidation: false,
    validationMethod: 'NONE',
    falsePositiveExclusions: [
      'changeme / example / placeholder / dummy / sample / redacted / test-only / process.env.*',
      'SHA-256 hex fixtures with repeated zeroes',
    ],
    remediation: 'Injetar segredos exclusivamente via variáveis de ambiente protegidas ou KMS.',
  },
];

const FALSE_POSITIVE_VALUE_REGEX =
  /^(?:example|sample|placeholder|changeme|your[_-]?key|dummy|fake|mock|test[_-]?secret|AKIAIOSFODNN7EXAMPLE|0{8,}|x{8,}|\*{4,})/i;

export function computeShannonEntropy(input: string): number {
  if (!input || input.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of input) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function maskDetectedSecret(raw: string): string {
  if (!raw) return '***';
  if (raw.length <= 8) return `${raw.slice(0, 2)}***`;
  return `${raw.slice(0, 4)}***${raw.slice(-3)}`;
}

export interface SecretScanOptions {
  allowOptInValidation?: boolean;
  validatorFn?: (patternId: string, redactedPreview: string) => Promise<{ valid: boolean; reason: string }>;
}

export class SecretScanner {
  public static getCatalogMetadata() {
    const checksumSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(SECRETS_PATTERN_CATALOG))
      .digest('hex');
    return {
      version: SECRETS_CATALOG_VERSION,
      patternsCount: SECRETS_PATTERN_CATALOG.length,
      checksumSha256,
      patterns: SECRETS_PATTERN_CATALOG,
      documentedExclusions: [
        'Strings matching placeholder/example markers (example, dummy, changeme, AKIAIOSFODNN7EXAMPLE, ****).',
        'Assignments referencing environment variables or KMS helpers rather than literal values.',
        'Low-entropy literals below pattern minShannonEntropy threshold.',
        'Files inside explicitly ignored fixtures/test mocks when marked NOSONAR, test-placeholder, or winhood-benchmark-corpus.',
      ],
    };
  }

  public static scanFiles(
    filesMap: Record<string, string>,
    _options?: SecretScanOptions
  ): AstIssueCandidate[] {
    const issues: AstIssueCandidate[] = [];
    const seen = new Set<string>();
    const sortedPaths = Object.keys(filesMap).sort((a, b) => a.localeCompare(b));

    for (const filePath of sortedPaths) {
      const content = filesMap[filePath] || '';
      if (!content) continue;
      // Skip intentionally vulnerable synthetic SAST/benchmark corpus definition files
      if (content.slice(0, 200).includes('winhood-benchmark-corpus: synthetic-sast-fixtures')) {
        continue;
      }
      // Ignore lockfiles or documentation-only markdown unless explicit PEM/token
      const isDocOrLock = /\.(md|txt|lock)$/i.test(filePath) || filePath.endsWith('package-lock.json');
      const lines = content.split(/\r?\n/);

      for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
        const line = lines[lineIdx] || '';
        const lineNo = lineIdx + 1;
        if (!line.trim() || /NOSONAR|winhood-ignore-secret/i.test(line)) continue;

        for (const pat of SECRETS_PATTERN_CATALOG) {
          if (isDocOrLock && pat.patternId === 'sec-generic-high-entropy-secret') continue;
          const regex = new RegExp(pat.regexSource, pat.regexFlags);
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            const captured = match[1] || match[0] || '';
            if (!captured || FALSE_POSITIVE_VALUE_REGEX.test(captured)) continue;
            if (/(?:^env\.|process\.env|os\.environ|\$\{[A-Z0-9_]+\})/i.test(captured)) continue;

            const entropy = computeShannonEntropy(captured);
            if (entropy < pat.minShannonEntropy) continue;

            const dedupKey = `${pat.ruleId}|${filePath}|${lineNo}`;
            if (seen.has(dedupKey)) continue;
            seen.add(dedupKey);

            const masked = maskDetectedSecret(captured);
            const redactedSnippet = line.replace(captured, masked).trim().slice(0, 220);

            issues.push({
              ruleId: pat.ruleId,
              title: `${pat.name} detectado no código`,
              description: `Padrão ${pat.patternId} (v${pat.version}) identificou segredo com entropia Shannon de ${entropy.toFixed(2)} bits/char (valor mascarado: ${masked}).`,
              category: 'SECRETS',
              severity: pat.severity,
              cwe: pat.cwe,
              filePath,
              lineNumber: lineNo,
              endLineNumber: lineNo,
              snippet: redactedSnippet,
              remediation: pat.remediation,
              detectionMethod: 'STATIC_PATTERN',
              confidence: entropy >= pat.minShannonEntropy + 0.5 ? 'HIGH' : 'MEDIUM',
              effortMinutes: 25,
            });
          }
        }
      }
    }

    return issues;
  }
}
