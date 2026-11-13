export interface GoldenDatasetCase {
  caseId: string;
  title: string;
  language: 'TypeScript' | 'JavaScript' | 'Python' | 'Java' | 'C#' | 'Go' | 'Rust' | 'SQL';
  category: 'SQL_INJECTION' | 'COMMAND_INJECTION' | 'CODE_INJECTION' | 'HARDCODED_SECRET' | 'WEAK_CRYPTO' | 'ERROR_HANDLING' | 'SQL_SCHEMA';
  cwe: string;
  expectedVulnerable: boolean;
  filesMap: Record<string, string>;
}

export const GOLDEN_DATASET_VERSION = 'WINHOOD-OWASP-CALIBRATION-v2.0.0';

/**
 * Corpus oficial de referência (True Positives + True Negatives pareados) inspirado no OWASP Benchmark.
 * Permite aferir objetivamente Precision, Recall, F1, FPR e FNR sobre o motor real ParserRegistry + TaintAnalyzer.
 */
export const GOLDEN_DATASET_CORPUS: GoldenDatasetCase[] = [
  // --- SQL INJECTION (TP vs TN) ---
  {
    caseId: 'GOLD-TS-SQLI-TP-01',
    title: 'TypeScript SQL Injection via concatenação direta em query',
    language: 'TypeScript',
    category: 'SQL_INJECTION',
    cwe: 'CWE-89',
    expectedVulnerable: true,
    filesMap: {
      'src/repo/userRepo.ts': [
        'export function findUserByTitle(db: any, userTitle: string) {',
        '  const sql = "SELECT id, email FROM users WHERE title = \'" + userTitle + "\'";',
        '  return db.query(sql);',
        '}',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-TS-SQLI-TN-01',
    title: 'TypeScript Prepared Statement parametrizado seguro',
    language: 'TypeScript',
    category: 'SQL_INJECTION',
    cwe: 'CWE-89',
    expectedVulnerable: false,
    filesMap: {
      'src/repo/userRepoSafe.ts': [
        'export function findUserByTitleSafe(db: any, userTitle: string) {',
        '  const sql = "SELECT id, email FROM users WHERE title = ?";',
        '  return db.query(sql, [userTitle]);',
        '}',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-TS-TAINT-CROSSFILE-TP-02',
    title: 'Fluxo Taint interprocedural cross-file Controller -> Repository SQLi',
    language: 'TypeScript',
    category: 'SQL_INJECTION',
    cwe: 'CWE-89',
    expectedVulnerable: true,
    filesMap: {
      'src/controller/searchCtrl.ts': [
        'import { runRawSearch } from "../db/searchRepo";',
        'export function handleSearch(queryInput: string) {',
        '  const cleanedInput = queryInput.trim();',
        '  return runRawSearch(cleanedInput);',
        '}',
      ].join('\n'),
      'src/db/searchRepo.ts': [
        'export function runRawSearch(filterExpr: string, db: any) {',
        '  const stmt = `SELECT id, name FROM entries WHERE name = ${filterExpr}`;',
        '  return db.query(stmt);',
        '}',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-TS-TAINT-SANITIZED-TN-02',
    title: 'Fluxo Taint com allowlist / sanitizador antes do sink',
    language: 'TypeScript',
    category: 'SQL_INJECTION',
    cwe: 'CWE-89',
    expectedVulnerable: false,
    filesMap: {
      'src/controller/searchSafeCtrl.ts': [
        'export function handleSearchSafe(db: any, rawId: string) {',
        '  const safeId = parseInt(rawId, 10);',
        '  return db.query("SELECT id, name FROM entries WHERE id = ?", [safeId]);',
        '}',
      ].join('\n'),
    },
  },

  // --- COMMAND INJECTION (TP vs TN) ---
  {
    caseId: 'GOLD-TS-CMDI-TP-03',
    title: 'TypeScript OS Command Injection com execSync interpolado',
    language: 'TypeScript',
    category: 'COMMAND_INJECTION',
    cwe: 'CWE-78',
    expectedVulnerable: true,
    filesMap: {
      'src/ops/backupRunner.ts': [
        'import { execSync } from "node:child_process";',
        'export function archiveFolder(targetPath: string) {',
        '  return execSync(`tar -czf backup.tar.gz ${targetPath}`);',
        '}',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-TS-CMDI-TN-03',
    title: 'TypeScript execução segura via execFile com array de argumentos',
    language: 'TypeScript',
    category: 'COMMAND_INJECTION',
    cwe: 'CWE-78',
    expectedVulnerable: false,
    filesMap: {
      'src/ops/backupRunnerSafe.ts': [
        'import { execFileSync } from "node:child_process";',
        'export function archiveFolderSafe(targetPath: string) {',
        '  return execFileSync("tar", ["-czf", "backup.tar.gz", targetPath], { shell: false });',
        '}',
      ].join('\n'),
    },
  },

  // --- CODE INJECTION (TP vs TN) ---
  {
    caseId: 'GOLD-JS-EVAL-TP-04',
    title: 'JavaScript uso inseguro de eval com entrada de usuário',
    language: 'JavaScript',
    category: 'CODE_INJECTION',
    cwe: 'CWE-95',
    expectedVulnerable: true,
    filesMap: {
      'src/calc/exprEngine.js': [
        'export function evaluateRule(userExpr) {',
        '  return eval(userExpr);',
        '}',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-JS-EVAL-TN-04',
    title: 'JavaScript avaliação segura por mapa de operações estático',
    language: 'JavaScript',
    category: 'CODE_INJECTION',
    cwe: 'CWE-95',
    expectedVulnerable: false,
    filesMap: {
      'src/calc/exprEngineSafe.js': [
        'export function evaluateRuleSafe(op, a, b) {',
        '  const ops = { add: (x, y) => x + y, sub: (x, y) => x - y };',
        '  return ops[op] ? ops[op](Number(a), Number(b)) : 0;',
        '}',
      ].join('\n'),
    },
  },

  // --- PYTHON (TP vs TN) ---
  {
    caseId: 'GOLD-PY-EXEC-TP-05',
    title: 'Python subprocess.run com shell=True',
    language: 'Python',
    category: 'COMMAND_INJECTION',
    cwe: 'CWE-78',
    expectedVulnerable: true,
    filesMap: {
      'app/runner.py': [
        'import subprocess',
        'def run_report(target):',
        '    return subprocess.run(f"ls -la {target}", shell=True)',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-PY-EXEC-TN-05',
    title: 'Python subprocess.run sem shell e lista de argumentos',
    language: 'Python',
    category: 'COMMAND_INJECTION',
    cwe: 'CWE-78',
    expectedVulnerable: false,
    filesMap: {
      'app/runner_safe.py': [
        'import subprocess',
        'def run_report_safe(target):',
        '    return subprocess.run(["ls", "-la", target], shell=False)',
      ].join('\n'),
    },
  },

  // --- JAVA (TP vs TN) ---
  {
    caseId: 'GOLD-JAVA-SQLI-TP-06',
    title: 'Java Statement.executeQuery com concatenação de entrada',
    language: 'Java',
    category: 'SQL_INJECTION',
    cwe: 'CWE-89',
    expectedVulnerable: true,
    filesMap: {
      'src/main/java/UserDao.java': [
        'public class UserDao {',
        '  public void findUser(java.sql.Statement stmt, String username) throws Exception {',
        '    stmt.executeQuery("SELECT id, name FROM users WHERE name = \'" + username + "\'");',
        '  }',
        '}',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-JAVA-SQLI-TN-06',
    title: 'Java PreparedStatement seguro com bind de parâmetro',
    language: 'Java',
    category: 'SQL_INJECTION',
    cwe: 'CWE-89',
    expectedVulnerable: false,
    filesMap: {
      'src/main/java/UserDaoSafe.java': [
        'public class UserDaoSafe {',
        '  public void findUser(java.sql.Connection conn, String username) throws Exception {',
        '    var ps = conn.prepareStatement("SELECT id, name FROM users WHERE name = ?");',
        '    ps.setString(1, username);',
        '    ps.executeQuery();',
        '  }',
        '}',
      ].join('\n'),
    },
  },

  // --- HARDCODED SECRETS & WEAK CRYPTO (TP vs TN) ---
  {
    caseId: 'GOLD-TS-SECRET-TP-07',
    title: 'Chave secreta hardcoded no código-fonte',
    language: 'TypeScript',
    category: 'HARDCODED_SECRET',
    cwe: 'CWE-798',
    expectedVulnerable: true,
    filesMap: {
      'src/config/authCfg.ts': [
        'export const masterKey = "SuperSecretProdMasterKey_9988776655";',
        'export function getMasterKey() { return masterKey; }',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-TS-SECRET-TN-07',
    title: 'Leitura de segredo exclusivamente via variável de ambiente',
    language: 'TypeScript',
    category: 'HARDCODED_SECRET',
    cwe: 'CWE-798',
    expectedVulnerable: false,
    filesMap: {
      'src/config/authCfgSafe.ts': [
        'export function getMasterKeySafe(): string {',
        '  const key = process.env.APP_MASTER_KEY;',
        '  if (!key) throw new Error("APP_MASTER_KEY ausente");',
        '  return key;',
        '}',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-TS-CRYPTO-TP-08',
    title: 'Derivação/hash inseguro com MD5 para credenciais',
    language: 'TypeScript',
    category: 'WEAK_CRYPTO',
    cwe: 'CWE-327',
    expectedVulnerable: true,
    filesMap: {
      'src/crypto/legacyHash.ts': [
        'import crypto from "node:crypto";',
        'export function hashPasswordLegacy(pwd: string) {',
        '  return crypto.createHash("md5").update(pwd).digest("hex");',
        '}',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-TS-CRYPTO-TN-08',
    title: 'Derivação forte PBKDF2-SHA512 com salt CSPRNG',
    language: 'TypeScript',
    category: 'WEAK_CRYPTO',
    cwe: 'CWE-327',
    expectedVulnerable: false,
    filesMap: {
      'src/crypto/strongHash.ts': [
        'import crypto from "node:crypto";',
        'export function hashPasswordStrong(pwd: string, salt: Buffer) {',
        '  return crypto.pbkdf2Sync(pwd, salt, 600000, 64, "sha512").toString("hex");',
        '}',
      ].join('\n'),
    },
  },

  // --- EXCEPTION HANDLING & SQL SCHEMA (TP vs TN) ---
  {
    caseId: 'GOLD-TS-CATCH-TP-09',
    title: 'Bloco catch vazio silenciando falha operacional',
    language: 'TypeScript',
    category: 'ERROR_HANDLING',
    cwe: 'CWE-390',
    expectedVulnerable: true,
    filesMap: {
      'src/service/syncService.ts': [
        'export function syncData(fn: () => void) {',
        '  try {',
        '    fn();',
        '  } catch (err) {',
        '  }',
        '}',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-TS-CATCH-TN-09',
    title: 'Bloco catch com tratamento explícito e propagação de erro',
    language: 'TypeScript',
    category: 'ERROR_HANDLING',
    cwe: 'CWE-390',
    expectedVulnerable: false,
    filesMap: {
      'src/service/syncServiceSafe.ts': [
        'export function syncDataSafe(fn: () => void) {',
        '  try {',
        '    fn();',
        '  } catch (err) {',
        '    console.error("Sync failure", err);',
        '    throw err;',
        '  }',
        '}',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-SQL-SCHEMA-TP-10',
    title: 'SQL SELECT * e coluna sensível password_plain em DDL',
    language: 'SQL',
    category: 'SQL_SCHEMA',
    cwe: 'CWE-312',
    expectedVulnerable: true,
    filesMap: {
      'db/schema.sql': [
        'CREATE TABLE vault_accounts (',
        '  id INTEGER PRIMARY KEY,',
        '  username TEXT NOT NULL,',
        '  password_plain TEXT NOT NULL',
        ');',
        'SELECT * FROM vault_accounts;',
      ].join('\n'),
    },
  },
  {
    caseId: 'GOLD-SQL-SCHEMA-TN-10',
    title: 'SQL DDL com colunas explícitas e hash de credencial',
    language: 'SQL',
    category: 'SQL_SCHEMA',
    cwe: 'CWE-312',
    expectedVulnerable: false,
    filesMap: {
      'db/schema_safe.sql': [
        'CREATE TABLE vault_accounts (',
        '  id INTEGER PRIMARY KEY,',
        '  username TEXT NOT NULL,',
        '  password_hash TEXT NOT NULL',
        ');',
        'SELECT id, username FROM vault_accounts WHERE id = ?;',
      ].join('\n'),
    },
  },
];
