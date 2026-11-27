/* winhood-benchmark-corpus: synthetic-sast-fixtures */
import crypto from 'node:crypto';
import type { GoldenDatasetOriginLabel, GoldenDatasetRole } from '../../types/benchmark';

export type SupportedBenchmarkLanguage =
  | 'TypeScript'
  | 'JavaScript'
  | 'Python'
  | 'Java'
  | 'C#'
  | 'Go'
  | 'Rust'
  | 'SQL';

export const DECLARED_BENCHMARK_LANGUAGES: ReadonlyArray<SupportedBenchmarkLanguage> = [
  'TypeScript',
  'JavaScript',
  'Python',
  'Java',
  'C#',
  'Go',
  'Rust',
  'SQL',
];

export type GoldenDatasetCategory =
  | 'SQL_INJECTION'
  | 'COMMAND_INJECTION'
  | 'CODE_INJECTION'
  | 'HARDCODED_SECRET'
  | 'WEAK_CRYPTO'
  | 'ERROR_HANDLING'
  | 'SQL_SCHEMA'
  | 'MEMORY_SAFETY';

export interface GoldenDatasetCaseInput {
  caseId: string;
  title: string;
  language: SupportedBenchmarkLanguage;
  category: GoldenDatasetCategory;
  cwe: string;
  expectedVulnerable: boolean;
  filesMap: Record<string, string>;
  origin?: string;
  license?: string;
  changelog?: string;
}

export interface GoldenDatasetCase extends GoldenDatasetCaseInput {
  origin: string;
  license: string;
  contentSha256: string;
  datasetVersion: string;
  datasetRole: GoldenDatasetRole;
  changelog: string;
}

export function computeGoldenCaseContentSha256(filesMap: Record<string, string>): string {
  const orderedEntries = Object.keys(filesMap)
    .sort((a, b) => a.localeCompare(b))
    .map((k) => [k, filesMap[k]]);
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(orderedEntries), 'utf8')
    .digest('hex');
}

function hydrateCorpus(
  rawCases: GoldenDatasetCaseInput[],
  datasetVersion: string,
  datasetRole: GoldenDatasetRole
): GoldenDatasetCase[] {
  return rawCases.map((item) => ({
    ...item,
    origin: item.origin || 'WINHOOD_INTERNAL_AUTHORED_FIXTURE',
    license: item.license || 'MIT',
    contentSha256: computeGoldenCaseContentSha256(item.filesMap),
    datasetVersion,
    datasetRole,
    changelog:
      item.changelog ||
      `[${datasetVersion}] Caso estruturado no conjunto ${datasetRole} com rastreabilidade SHA-256.`,
  }));
}

export const DEVELOPMENT_DATASET_VERSION = 'WINHOOD-DEVELOPMENT-v3.0.0';
export const DEVELOPMENT_DATASET_ORIGIN_LABEL: GoldenDatasetOriginLabel =
  'WINHOOD_INTERNAL_DEVELOPMENT_CORPUS';

export const GOLDEN_DATASET_VERSION = 'WINHOOD-INTERNAL-REGRESSION-v3.0.0';
export const GOLDEN_DATASET_ORIGIN_LABEL: GoldenDatasetOriginLabel =
  'WINHOOD_INTERNAL_REGRESSION_CORPUS';

export const INTERNAL_HOLDOUT_VERSION = 'WINHOOD-INTERNAL-HOLDOUT-v3.0.0';
export const INTERNAL_HOLDOUT_ORIGIN_LABEL: GoldenDatasetOriginLabel =
  'WINHOOD_INTERNAL_HOLDOUT_CORPUS';

/**
 * Conjunto 1: DESENVOLVIMENTO (DEVELOPMENT)
 * Casos sintéticos para calibração exploratória e prototipagem de novas regras.
 * Separado dos conjuntos de Regressão e Holdout Interno.
 */
export const DEVELOPMENT_DATASET_CORPUS: GoldenDatasetCase[] = hydrateCorpus(
  [
    {
      caseId: 'DEV-TS-SQLI-TP-01',
      title: 'Dev Calibration: TypeScript template literal SQLi em serviço auxiliar',
      language: 'TypeScript',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: true,
      filesMap: {
        'src/dev/reportRepo.ts': [
          'export function queryReport(db: any, tenantSlug: string) {',
          '  const q = `SELECT id FROM reports WHERE tenant = \'${tenantSlug}\'`;',
          '  return db.query(q);',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-DEVELOPMENT-v3.0.0] Caso inicial de calibração TS SQLi.',
    },
    {
      caseId: 'DEV-TS-SQLI-TN-01',
      title: 'Dev Calibration: TypeScript prepared statement parametrizado',
      language: 'TypeScript',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: false,
      filesMap: {
        'src/dev/reportSafeRepo.ts': [
          'export function queryReportSafe(db: any, tenantSlug: string) {',
          '  return db.query("SELECT id FROM reports WHERE tenant = ?", [tenantSlug]);',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-DEVELOPMENT-v3.0.0] Controle negativo parametrizado TS.',
    },
    {
      caseId: 'DEV-PY-CRYPTO-TP-02',
      title: 'Dev Calibration: Python hashlib.md5 em token de sessão',
      language: 'Python',
      category: 'WEAK_CRYPTO',
      cwe: 'CWE-328',
      expectedVulnerable: true,
      filesMap: {
        'dev/token_gen.py': [
          'import hashlib',
          'def session_digest(raw_value):',
          '    return hashlib.md5(raw_value).hexdigest()',
        ].join('\n'),
      },
      changelog: '[WINHOOD-DEVELOPMENT-v3.0.0] Caso inicial Python weak hash.',
    },
    {
      caseId: 'DEV-PY-CRYPTO-TN-02',
      title: 'Dev Calibration: Python hashlib.sha256 seguro',
      language: 'Python',
      category: 'WEAK_CRYPTO',
      cwe: 'CWE-328',
      expectedVulnerable: false,
      filesMap: {
        'dev/token_gen_safe.py': [
          'import hashlib',
          'def session_digest_safe(raw_value):',
          '    return hashlib.sha256(raw_value).hexdigest()',
        ].join('\n'),
      },
      changelog: '[WINHOOD-DEVELOPMENT-v3.0.0] Controle negativo Python SHA-256.',
    },
  ],
  DEVELOPMENT_DATASET_VERSION,
  'DEVELOPMENT'
);

/**
 * Conjunto 2: REGRESSÃO DETERMINÍSTICA (REGRESSION)
 * Corpus interno pareado TP/TN nas 8 linguagens declaradas para detecção de regressão entre commits.
 * NÃO constitui benchmark externo independente (ver limitações estatísticas no relatório).
 */
export const GOLDEN_DATASET_CORPUS: GoldenDatasetCase[] = hydrateCorpus(
  [
    // --- TYPESCRIPT ---
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
      title: 'TypeScript execução segura via execFileSync com array de argumentos',
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

    // --- JAVASCRIPT ---
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

    // --- PYTHON ---
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

    // --- JAVA ---
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

    // --- SECRETS, CRYPTO, ERROR HANDLING ---
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

    // --- SQL ---
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

    // --- C# (ADDED FOR 8-LANGUAGE COVERAGE) ---
    {
      caseId: 'GOLD-CS-SQLI-TP-11',
      title: 'C# SqlCommand.ExecuteReader com concatenação direta de entrada',
      language: 'C#',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: true,
      filesMap: {
        'src/Data/AccountRepository.cs': [
          'using System.Data.SqlClient;',
          'public class AccountRepository {',
          '  public void FetchAccount(SqlCommand cmd, string accountName) {',
          '    cmd.ExecuteReader("SELECT Id, Email FROM Accounts WHERE Name = \'" + accountName + "\'");',
          '  }',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-INTERNAL-REGRESSION-v3.0.0] Adicionado par TP/TN para C# SQLi.',
    },
    {
      caseId: 'GOLD-CS-SQLI-TN-11',
      title: 'C# consulta parametrizada segura com SqlParameter',
      language: 'C#',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: false,
      filesMap: {
        'src/Data/AccountSafeRepository.cs': [
          'using System.Data.SqlClient;',
          'public class AccountSafeRepository {',
          '  public void FetchAccountSafe(SqlConnection conn, string accountName) {',
          '    var cmd = new SqlCommand("SELECT Id, Email FROM Accounts WHERE Name = @name", conn);',
          '    cmd.Parameters.Add(new SqlParameter("@name", accountName));',
          '  }',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-INTERNAL-REGRESSION-v3.0.0] Adicionado controle TN C# SqlParameter.',
    },

    // --- GO (ADDED FOR 8-LANGUAGE COVERAGE) ---
    {
      caseId: 'GOLD-GO-SQLI-TP-12',
      title: 'Go database/sql Query com fmt.Sprintf interpolado',
      language: 'Go',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: true,
      filesMap: {
        'internal/repo/customer_repo.go': [
          'package repo',
          'import "fmt"',
          'func FindCustomer(db DB, slug string) error {',
          '  _, err := db.Query(fmt.Sprintf("SELECT id FROM customers WHERE slug = \'%s\'", slug))',
          '  return err',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-INTERNAL-REGRESSION-v3.0.0] Adicionado par TP/TN para Go SQLi.',
    },
    {
      caseId: 'GOLD-GO-SQLI-TN-12',
      title: 'Go database/sql Query com placeholder posicional ($1)',
      language: 'Go',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: false,
      filesMap: {
        'internal/repo/customer_safe_repo.go': [
          'package repo',
          'func FindCustomerSafe(db DB, slug string) error {',
          '  _, err := db.Query("SELECT id FROM customers WHERE slug = $1", slug)',
          '  return err',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-INTERNAL-REGRESSION-v3.0.0] Adicionado controle TN Go SQL parametrizado.',
    },

    // --- RUST (ADDED FOR 8-LANGUAGE COVERAGE) ---
    {
      caseId: 'GOLD-RUST-SECRET-TP-13',
      title: 'Rust credencial hardcoded atribuída em variável literal',
      language: 'Rust',
      category: 'HARDCODED_SECRET',
      cwe: 'CWE-798',
      expectedVulnerable: true,
      filesMap: {
        'src/auth/token_signer.rs': [
          'pub fn get_signing_secret() -> &\'static str {',
          '  let jwt_secret = "RustProdSigningKey_9182736450_Vault";',
          '  jwt_secret',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-INTERNAL-REGRESSION-v3.0.0] Adicionado par TP/TN para Rust CWE-798.',
    },
    {
      caseId: 'GOLD-RUST-SECRET-TN-13',
      title: 'Rust leitura segura de credencial via std::env::var',
      language: 'Rust',
      category: 'HARDCODED_SECRET',
      cwe: 'CWE-798',
      expectedVulnerable: false,
      filesMap: {
        'src/auth/token_signer_safe.rs': [
          'pub fn get_signing_secret_safe() -> String {',
          '  std::env::var("WINHOOD_SIGNING_SECRET").expect("Secret env missing")',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-INTERNAL-REGRESSION-v3.0.0] Adicionado controle TN Rust env var.',
    },
  ],
  GOLDEN_DATASET_VERSION,
  'REGRESSION'
);

/**
 * Conjunto 3: HOLDOUT INTERNO RESERVADO (INTERNAL_HOLDOUT)
 * Conjunto reservado de autoria interna cobrindo todas as 8 linguagens declaradas,
 * mantido separado do ajuste de heurísticas de desenvolvimento.
 * NOTA METODOLÓGICA: Não substitui um benchmark externo independente de terceiros (ex.: OWASP Benchmark v1.2).
 */
export const INTERNAL_HOLDOUT_CORPUS: GoldenDatasetCase[] = hydrateCorpus(
  [
    {
      caseId: 'HOLD-TS-SQLI-TP-01',
      title: 'Holdout Interno: TypeScript SQLi em relatório financeiro interpolado',
      language: 'TypeScript',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: true,
      filesMap: {
        'src/finance/ledgerDao.ts': [
          'export function queryLedgerByAccount(conn: any, accountCode: string) {',
          '  const queryText = `SELECT balance, currency FROM ledger WHERE account_code = \'${accountCode}\'`;',
          '  return conn.query(queryText);',
          '}',
        ].join('\n'),
      },
    },
    {
      caseId: 'HOLD-TS-SQLI-TN-01',
      title: 'Holdout Interno: TypeScript SQLi mitigado por conversão numérica Number()',
      language: 'TypeScript',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: false,
      filesMap: {
        'src/finance/ledgerSafeDao.ts': [
          'export function queryLedgerByNumericId(conn: any, rawAccountId: string) {',
          '  const numericId = Number(rawAccountId);',
          '  return conn.query("SELECT balance FROM ledger WHERE id = $1", [numericId]);',
          '}',
        ].join('\n'),
      },
    },
    {
      caseId: 'HOLD-JS-CMDI-TP-02',
      title: 'Holdout Interno: JavaScript Command Injection via child_process.execSync',
      language: 'JavaScript',
      category: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      expectedVulnerable: true,
      filesMap: {
        'src/ops/archiveWorker.js': [
          'import { execSync } from "node:child_process";',
          'export function compressFolder(targetFolder) {',
          '  return execSync("tar -cf archive.tar " + targetFolder);',
          '}',
        ].join('\n'),
      },
    },
    {
      caseId: 'HOLD-JS-CMDI-TN-02',
      title: 'Holdout Interno: JavaScript spawnSync seguro com shell: false',
      language: 'JavaScript',
      category: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      expectedVulnerable: false,
      filesMap: {
        'src/ops/archiveWorkerSafe.js': [
          'import { spawnSync } from "node:child_process";',
          'export function compressFolderSafe(targetFolder) {',
          '  return spawnSync("tar", ["-cf", "archive.tar", targetFolder], { shell: false });',
          '}',
        ].join('\n'),
      },
    },
    {
      caseId: 'HOLD-PY-SQLI-TP-03',
      title: 'Holdout Interno: Python SQL Injection com concatenação em cursor.execute',
      language: 'Python',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: true,
      filesMap: {
        'app/orders_repo.py': [
          'def fetch_order_by_code(cursor, order_code):',
          '    stmt = "SELECT id, total FROM orders WHERE code = \'" + order_code + "\'"',
          '    cursor.execute(stmt)',
        ].join('\n'),
      },
    },
    {
      caseId: 'HOLD-PY-SQLI-TN-03',
      title: 'Holdout Interno: Python cursor.execute parametrizado',
      language: 'Python',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: false,
      filesMap: {
        'app/orders_repo_safe.py': [
          'def fetch_order_by_code_safe(cursor, order_code):',
          '    cursor.execute("SELECT id, total FROM orders WHERE code = %s", (order_code,))',
        ].join('\n'),
      },
    },
    {
      caseId: 'HOLD-PY-CRYPTO-TP-04',
      title: 'Holdout Interno: Python hashlib.sha1 para digest de credencial',
      language: 'Python',
      category: 'WEAK_CRYPTO',
      cwe: 'CWE-328',
      expectedVulnerable: true,
      filesMap: {
        'app/legacy_hasher.py': [
          'import hashlib',
          'def compute_legacy_digest(payload_bytes):',
          '    return hashlib.sha1(payload_bytes).hexdigest()',
        ].join('\n'),
      },
    },
    {
      caseId: 'HOLD-PY-CRYPTO-TN-04',
      title: 'Holdout Interno: Python hashlib.pbkdf2_hmac SHA-256 seguro',
      language: 'Python',
      category: 'WEAK_CRYPTO',
      cwe: 'CWE-328',
      expectedVulnerable: false,
      filesMap: {
        'app/modern_hasher.py': [
          'import hashlib',
          'def compute_kdf_digest(payload_bytes, salt_bytes):',
          '    return hashlib.pbkdf2_hmac("sha256", payload_bytes, salt_bytes, 600000)',
        ].join('\n'),
      },
    },
    {
      caseId: 'HOLD-JAVA-SQLI-TP-05',
      title: 'Holdout Interno: Java executeQuery com concatenação',
      language: 'Java',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: true,
      filesMap: {
        'src/main/java/InvoiceDao.java': [
          'public class InvoiceDao {',
          '  public void queryInvoice(Statement st, String code) throws Exception {',
          '    st.executeQuery("SELECT id FROM invoices WHERE code = \'" + code + "\'");',
          '  }',
          '}',
        ].join('\n'),
      },
    },
    {
      caseId: 'HOLD-JAVA-SQLI-TN-05',
      title: 'Holdout Interno: Java PreparedStatement seguro',
      language: 'Java',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: false,
      filesMap: {
        'src/main/java/InvoiceSafeDao.java': [
          'public class InvoiceSafeDao {',
          '  public void queryInvoiceSafe(Connection conn, String code) throws Exception {',
          '    PreparedStatement ps = conn.prepareStatement("SELECT id FROM invoices WHERE code = ?");',
          '  }',
          '}',
        ].join('\n'),
      },
    },
    {
      caseId: 'HOLD-CS-CRYPTO-TP-06',
      title: 'Holdout Interno: C# derivação de hash fraco MD5',
      language: 'C#',
      category: 'WEAK_CRYPTO',
      cwe: 'CWE-328',
      expectedVulnerable: true,
      filesMap: {
        'src/Security/LegacyDigest.cs': [
          'using System.Security.Cryptography;',
          'public class LegacyDigest {',
          '  public byte[] ComputeWeak(byte[] data) {',
          '    using var md5 = MD5.Create();',
          '    return md5.ComputeHash(data);',
          '  }',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-INTERNAL-HOLDOUT-v3.0.0] Cobertura C# adicionada ao Holdout Interno.',
    },
    {
      caseId: 'HOLD-CS-CRYPTO-TN-06',
      title: 'Holdout Interno: C# hash SHA-256 seguro',
      language: 'C#',
      category: 'WEAK_CRYPTO',
      cwe: 'CWE-328',
      expectedVulnerable: false,
      filesMap: {
        'src/Security/StrongDigest.cs': [
          'using System.Security.Cryptography;',
          'public class StrongDigest {',
          '  public byte[] ComputeStrong(byte[] data) {',
          '    using var sha = SHA256.Create();',
          '    return sha.ComputeHash(data);',
          '  }',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-INTERNAL-HOLDOUT-v3.0.0] Controle negativo C# SHA-256.',
    },
    {
      caseId: 'HOLD-GO-EXEC-TP-07',
      title: 'Holdout Interno: Go sql.Exec com concatenação direta de string',
      language: 'Go',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: true,
      filesMap: {
        'internal/audit/store.go': [
          'package audit',
          'func PurgeByTag(db DB, tag string) error {',
          '  _, err := db.Exec("DELETE FROM audit_tags WHERE tag = \'" + tag + "\'")',
          '  return err',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-INTERNAL-HOLDOUT-v3.0.0] Cobertura Go adicionada ao Holdout Interno.',
    },
    {
      caseId: 'HOLD-GO-EXEC-TN-07',
      title: 'Holdout Interno: Go sql.Exec parametrizado com $1',
      language: 'Go',
      category: 'SQL_INJECTION',
      cwe: 'CWE-89',
      expectedVulnerable: false,
      filesMap: {
        'internal/audit/store_safe.go': [
          'package audit',
          'func PurgeByTagSafe(db DB, tag string) error {',
          '  _, err := db.Exec("DELETE FROM audit_tags WHERE tag = $1", tag)',
          '  return err',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-INTERNAL-HOLDOUT-v3.0.0] Controle negativo Go SQL parametrizado.',
    },
    {
      caseId: 'HOLD-RUST-UNSAFE-TP-08',
      title: 'Holdout Interno: Rust bloco unsafe contornando verificação de memória',
      language: 'Rust',
      category: 'MEMORY_SAFETY',
      cwe: 'CWE-119',
      expectedVulnerable: true,
      filesMap: {
        'src/ffi/raw_ptr.rs': [
          'pub fn read_raw(ptr: *const u32) -> u32 {',
          '  unsafe {',
          '    *ptr',
          '  }',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-INTERNAL-HOLDOUT-v3.0.0] Cobertura Rust adicionada ao Holdout Interno.',
    },
    {
      caseId: 'HOLD-RUST-UNSAFE-TN-08',
      title: 'Holdout Interno: Rust acesso seguro via slice get()',
      language: 'Rust',
      category: 'MEMORY_SAFETY',
      cwe: 'CWE-119',
      expectedVulnerable: false,
      filesMap: {
        'src/ffi/safe_slice.rs': [
          'pub fn read_safe(items: &[u32], idx: usize) -> Option<u32> {',
          '  items.get(idx).copied()',
          '}',
        ].join('\n'),
      },
      changelog: '[WINHOOD-INTERNAL-HOLDOUT-v3.0.0] Controle negativo Rust safe slice.',
    },
    {
      caseId: 'HOLD-SQL-DDL-TP-09',
      title: 'Holdout Interno: SQL DELETE sem cláusula WHERE',
      language: 'SQL',
      category: 'SQL_SCHEMA',
      cwe: 'CWE-404',
      expectedVulnerable: true,
      filesMap: {
        'db/cleanup.sql': [
          'CREATE TABLE audit_events (id INT PRIMARY KEY, event_name VARCHAR(80));',
          'DELETE FROM audit_events;',
        ].join('\n'),
      },
    },
    {
      caseId: 'HOLD-SQL-DDL-TN-09',
      title: 'Holdout Interno: SQL DELETE restrito por cláusula WHERE',
      language: 'SQL',
      category: 'SQL_SCHEMA',
      cwe: 'CWE-404',
      expectedVulnerable: false,
      filesMap: {
        'db/cleanup_safe.sql': [
          'CREATE TABLE audit_events (id INT PRIMARY KEY, event_name VARCHAR(80));',
          'DELETE FROM audit_events WHERE id = 100;',
        ].join('\n'),
      },
    },
  ],
  INTERNAL_HOLDOUT_VERSION,
  'INTERNAL_HOLDOUT'
);
