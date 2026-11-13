import crypto from 'node:crypto';
import type { RuleDefinition, RulePackMetadata, SupportedAstLanguage } from './types';

export const BUILTIN_RULES: RuleDefinition[] = [
  {
    ruleId: 'ts:S3649',
    title: 'SQL Injection via concatenação ou interpolação de string',
    category: 'SAST',
    severity: 'BLOCKER',
    cwe: 'CWE-89',
    languages: ['TypeScript', 'JavaScript'],
    requiresAst: true,
    effortMinutes: 30,
    remediation: 'Substituir por Prepared Statements parametrizados (? ou $1).',
    packId: 'winhood-mqr-core',
  },
  {
    ruleId: 'taint:S3649',
    title: 'SQL Injection interprocedural / cross-file (Source -> Sink)',
    category: 'SAST',
    severity: 'BLOCKER',
    cwe: 'CWE-89',
    languages: ['TypeScript', 'JavaScript', 'Python', 'Java', 'C#', 'Go'],
    requiresAst: true,
    effortMinutes: 35,
    remediation: 'Sanitizar entrada na borda e utilizar queries parametrizadas no repositório.',
    packId: 'winhood-taint-core',
  },
  {
    ruleId: 'ts:S2076',
    title: 'OS Command Injection / eval dinâmico',
    category: 'SAST',
    severity: 'BLOCKER',
    cwe: 'CWE-78',
    languages: ['TypeScript', 'JavaScript'],
    requiresAst: true,
    effortMinutes: 30,
    remediation: 'Utilizar execFile/spawn com shell: false e validação estrita.',
    packId: 'winhood-mqr-core',
  },
  {
    ruleId: 'taint:S2076',
    title: 'Command Injection interprocedural (Source -> Sink)',
    category: 'SAST',
    severity: 'BLOCKER',
    cwe: 'CWE-78',
    languages: ['TypeScript', 'JavaScript', 'Python', 'Java', 'Go'],
    requiresAst: true,
    effortMinutes: 35,
    remediation: 'Eliminar invocação de shell com entrada controlada por usuário.',
    packId: 'winhood-taint-core',
  },
  {
    ruleId: 'ts:S6418',
    title: 'Segredo ou chave criptográfica hardcoded em código',
    category: 'SECRETS',
    severity: 'BLOCKER',
    cwe: 'CWE-798',
    languages: ['TypeScript', 'JavaScript', 'Python', 'Java', 'C#', 'Go', 'Rust'],
    requiresAst: true,
    effortMinutes: 25,
    remediation: 'Remover credenciais literais e usar KMS/Cofre/Variáveis de ambiente.',
    packId: 'winhood-mqr-core',
  },
  {
    ruleId: 'ts:S4790',
    title: 'Algoritmo criptográfico obsoleto (MD5/SHA-1)',
    category: 'SAST',
    severity: 'CRITICAL',
    cwe: 'CWE-328',
    languages: ['TypeScript', 'JavaScript', 'Python', 'Java', 'C#', 'Go', 'Rust'],
    requiresAst: true,
    effortMinutes: 20,
    remediation: 'Migrar para PBKDF2-SHA512 (>= 600k iterações), Argon2id ou SHA-256.',
    packId: 'winhood-mqr-core',
  },
  {
    ruleId: 'ts:S2245',
    title: 'PRNG inseguro Math.random() em código produtivo',
    category: 'SAST',
    severity: 'HIGH',
    cwe: 'CWE-338',
    languages: ['TypeScript', 'JavaScript'],
    requiresAst: true,
    effortMinutes: 15,
    remediation: 'Substituir por crypto.randomBytes() ou crypto.randomUUID().',
    packId: 'winhood-mqr-core',
  },
  {
    ruleId: 'ts:S2486',
    title: 'Bloco catch vazio silencia falhas',
    category: 'CODE_QUALITY',
    severity: 'HIGH',
    cwe: 'CWE-390',
    languages: ['TypeScript', 'JavaScript', 'Java', 'C#'],
    requiresAst: true,
    effortMinutes: 10,
    remediation: 'Tratar ou registrar exceção adequadamente.',
    packId: 'winhood-mqr-core',
  },
  {
    ruleId: 'ts:S1763',
    title: 'Código inalcançável (Dead Code)',
    category: 'CODE_QUALITY',
    severity: 'MEDIUM',
    cwe: 'CWE-561',
    languages: ['TypeScript', 'JavaScript'],
    requiresAst: true,
    effortMinutes: 5,
    remediation: 'Remover declarações após return/throw/break.',
    packId: 'winhood-mqr-core',
  },
  {
    ruleId: 'ts:S1128',
    title: 'Import não utilizado no módulo',
    category: 'CODE_QUALITY',
    severity: 'LOW',
    cwe: 'CWE-561',
    languages: ['TypeScript', 'JavaScript'],
    requiresAst: true,
    effortMinutes: 2,
    remediation: 'Remover símbolo importado sem referências.',
    packId: 'winhood-mqr-core',
  },
  {
    ruleId: 'ts:S4204',
    title: 'Uso de tipo explícito any',
    category: 'CODE_QUALITY',
    severity: 'LOW',
    cwe: 'CWE-710',
    languages: ['TypeScript'],
    requiresAst: true,
    effortMinutes: 5,
    remediation: 'Tipar interface explicitamente ou utilizar unknown.',
    packId: 'winhood-mqr-core',
  },
  {
    ruleId: 'sql:S2068',
    title: 'Coluna de credencial em texto plano no DDL SQL',
    category: 'DATABASE',
    severity: 'CRITICAL',
    cwe: 'CWE-256',
    languages: ['SQL'],
    requiresAst: true,
    effortMinutes: 30,
    remediation: 'Armazenar apenas ciphertext + iv + auth_tag + kdf_salt.',
    packId: 'winhood-sql-core',
  },
  {
    ruleId: 'sql:S1999',
    title: 'Uso de SELECT * sem lista explícita de colunas',
    category: 'DATABASE',
    severity: 'MEDIUM',
    cwe: 'CWE-200',
    languages: ['SQL'],
    requiresAst: true,
    effortMinutes: 10,
    remediation: 'Especificar colunas explícitas na consulta.',
    packId: 'winhood-sql-core',
  },
];

export class RuleRegistry {
  public static getAllRules(): RuleDefinition[] {
    return BUILTIN_RULES;
  }

  public static getRulesForLanguage(language: SupportedAstLanguage): RuleDefinition[] {
    return BUILTIN_RULES.filter((r) => r.languages.includes(language));
  }

  public static findRule(ruleId: string): RuleDefinition | undefined {
    return BUILTIN_RULES.find((r) => r.ruleId === ruleId);
  }
}

export class RulePackVersionManager {
  public static listRulePacks(): RulePackMetadata[] {
    const groups = new Map<string, RuleDefinition[]>();
    for (const rule of BUILTIN_RULES) {
      const list = groups.get(rule.packId) || [];
      list.push(rule);
      groups.set(rule.packId, list);
    }

    const packInfo: Record<string, { name: string; version: string }> = {
      'winhood-mqr-core': { name: 'WinHood MQR Core AST RulePack', version: '2026.11.0' },
      'winhood-taint-core': { name: 'WinHood Interprocedural Taint RulePack', version: '2026.11.0' },
      'winhood-sql-core': { name: 'WinHood SQL DDL/DML Structural RulePack', version: '2026.11.0' },
    };

    const result: RulePackMetadata[] = [];
    for (const [packId, rules] of groups.entries()) {
      const langs = Array.from(new Set(rules.flatMap((r) => r.languages)));
      const checksumSha256 = crypto
        .createHash('sha256')
        .update(JSON.stringify(rules))
        .digest('hex');
      result.push({
        packId,
        name: packInfo[packId]?.name || packId,
        version: packInfo[packId]?.version || '2026.11.0',
        releasedAt: '2026-11-13T00:00:00Z',
        rulesCount: rules.length,
        checksumSha256,
        languages: langs,
      });
    }
    return result;
  }
}
