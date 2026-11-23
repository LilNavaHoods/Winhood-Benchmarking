import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AnalyzerRegistry,
  buildCodeQlLifecycleCommands,
  detectCodeQlLanguage,
  EXTERNAL_STATIC_ENGINES,
} from './AnalyzerRegistry';
import { SarifCodec } from './SarifCodec';
import type { AnalysisScope } from './types';

const TEST_SCOPE: AnalysisScope = {
  runId: 'run-ext-adapters-1',
  softwareId: 'sw-ext-1',
  softwareName: 'TargetService',
  softwareVersion: '2.1.0',
  filesMap: {
    'src/app.ts': 'export const run = (x: string) => eval(x);\n',
    'src/query.py': 'import subprocess\nsubprocess.Popen(user_cmd, shell=True)\n',
    'src/Main.java': 'public class Main { public static void main(String[] a) {} }\n',
    'src/App.csproj': '<Project Sdk="Microsoft.NET.Sdk"></Project>\n',
  },
};

function getEngine(id: string) {
  const found = EXTERNAL_STATIC_ENGINES.find((e) => e.id === id);
  assert.ok(found, `Engine descriptor ${id} must exist`);
  return found;
}

test('SarifCodec.importSarif210 handles multi-run SARIF, missing locations, unknown severities, deduplication, suppressions, invalid payloads, and preserves UNVERIFIED provenance', () => {
  // Invalid payloads must be rejected cleanly
  assert.equal(SarifCodec.importSarif210(null, TEST_SCOPE).valid, false);
  assert.equal(SarifCodec.importSarif210({ version: '1.0.0', runs: [] }, TEST_SCOPE).valid, false);
  assert.equal(SarifCodec.importSarif210({ version: '2.1.0', runs: 'not-array' }, TEST_SCOPE).valid, false);

  const multiRunSarif = {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'CodeQL',
            version: '2.18.0',
            rules: [
              {
                id: 'js/sql-injection',
                shortDescription: { text: 'SQL Injection via tainted input' },
                properties: {
                  'security-severity': '9.4',
                  precision: 'very-high',
                  tags: ['security', 'external/cwe/cwe-089'],
                },
              },
            ],
          },
        },
        results: [
          {
            ruleId: 'js/sql-injection',
            level: 'error',
            message: { text: 'Unsanitized query parameter reaches SQL sink.' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'src/app.ts' },
                  region: { startLine: 10, endLine: 12, startColumn: 5, endColumn: 42, snippet: { text: 'db.query(sql)' } },
                },
              },
            ],
            codeFlows: [
              {
                threadFlows: [
                  {
                    locations: [
                      {
                        location: {
                          physicalLocation: { artifactLocation: { uri: 'src/app.ts' }, region: { startLine: 3 } },
                          message: { text: 'req.query.id' },
                        },
                      },
                      {
                        location: {
                          physicalLocation: { artifactLocation: { uri: 'src/app.ts' }, region: { startLine: 10 } },
                          message: { text: 'db.query(sql)' },
                        },
                      },
                    ],
                  },
                ],
              },
            ],
          },
          // Exact duplicate of first result -> must deduplicate
          {
            ruleId: 'js/sql-injection',
            level: 'error',
            message: { text: 'Unsanitized query parameter reaches SQL sink.' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'src/app.ts' },
                  region: { startLine: 10, startColumn: 5 },
                },
              },
            ],
          },
          // Missing physicalLocation + unrecognized severity + missing rule metadata
          {
            ruleId: 'custom/incomplete-rule',
            level: 'ultra-weird-level',
            message: { text: 'Issue without location metadata' },
          },
          // Suppressed finding -> ACCEPTED_RISK
          {
            ruleId: 'js/sql-injection',
            level: 'warning',
            message: { text: 'Reviewed legacy query' },
            suppressions: [{ kind: 'inSource', justification: 'Parameterized wrapper' }],
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'src/legacy.ts' },
                  region: { startLine: 44 },
                },
              },
            ],
          },
        ],
      },
      {
        tool: {
          driver: {
            name: 'SpotBugs',
            version: '4.8.6',
          },
        },
        results: [
          {
            ruleId: 'SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE',
            level: 'warning',
            message: { text: 'Nonconstant string passed to execute' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'src/Main.java' },
                  region: { startLine: 25, startColumn: 9 },
                },
              },
            ],
          },
        ],
      },
    ],
  };

  const imported = SarifCodec.importSarif210(multiRunSarif, TEST_SCOPE);
  assert.equal(imported.valid, true);
  assert.equal(imported.deduplicatedCount, 1);
  assert.deepEqual(imported.importedToolNames, ['CodeQL', 'SpotBugs']);
  assert.equal(imported.findings.length, 4);

  const sqli = imported.findings[0]!;
  assert.equal(sqli.originalRuleId, 'js/sql-injection');
  assert.equal(sqli.severity, 'CRITICAL');
  assert.equal(sqli.cvss, 9.4);
  assert.equal(sqli.cwe, 'CWE-089');
  assert.equal(sqli.columnStart, 5);
  assert.equal(sqli.columnEnd, 42);
  assert.equal(sqli.executionFlows?.length, 2);
  assert.equal(sqli.validationStatus, 'UNVERIFIED', 'External SARIF findings must never be auto-verified by WinHood');
  assert.equal(sqli.lifecycleState, 'UNVERIFIED');

  const noLoc = imported.findings[1]!;
  assert.equal(noLoc.filePath, 'unknown');
  assert.equal(noLoc.confidence, 'LOW');
  assert.equal(noLoc.validationStatus, 'UNVERIFIED');
  assert.ok(imported.warnings.length >= 2);

  const suppressed = imported.findings[2]!;
  assert.equal(suppressed.validationStatus, 'ACCEPTED_RISK');

  const spotbugs = imported.findings[3]!;
  assert.equal(spotbugs.toolName, 'SpotBugs');
  assert.equal(spotbugs.filePath, 'src/Main.java');
  assert.equal(spotbugs.validationStatus, 'UNVERIFIED');
});

test('AnalyzerRegistry parses SARIF (CodeQL/Roslyn/SpotBugs/Checkstyle), ESLint, Ruff, Bandit, Semgrep, and Gitleaks with strict schema validation', () => {
  // 1. SARIF via CodeQL / Roslyn / SpotBugs / Checkstyle
  const sarifFixture = JSON.stringify({
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'Roslyn', version: '4.11.0' } },
        results: [
          {
            ruleId: 'CA3001',
            level: 'error',
            message: { text: 'Review code for SQL injection vulnerabilities' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'src/Repo.cs' },
                  region: { startLine: 18, startColumn: 13 },
                },
              },
            ],
          },
        ],
      },
    ],
  });
  for (const engineId of ['codeql-cli', 'roslyn-analyzers', 'spotbugs-java', 'checkstyle-java']) {
    const out = AnalyzerRegistry.parseExternalJsonOutputWithValidation(
      getEngine(engineId),
      sarifFixture,
      TEST_SCOPE,
      '1.0.0'
    );
    assert.equal(out.validSchema, true, `${engineId} must accept valid SARIF 2.1.0`);
    assert.equal(out.findings.length, 1, `${engineId} must convert SARIF findings instead of returning empty array`);
    assert.equal(out.findings[0]!.originalRuleId, 'CA3001');
    assert.equal(out.findings[0]!.validationStatus, 'UNVERIFIED');
    assert.equal(out.findings[0]!.originType, 'EXTERNAL_TOOL_EXECUTION');
  }

  // 2. ESLint JSON (sev 2 -> HIGH, sev 1 -> MEDIUM, sev 0 -> ignored)
  const eslintFixture = JSON.stringify([
    {
      filePath: 'src/app.ts',
      messages: [
        {
          ruleId: 'no-eval',
          severity: 2,
          message: 'eval can be harmful.',
          line: 1,
          column: 35,
          endLine: 1,
          endColumn: 42,
          nodeType: 'CallExpression',
        },
        {
          ruleId: 'prefer-const',
          severity: 1,
          message: "'x' is never reassigned.",
          line: 4,
          column: 5,
          fix: { range: [0, 3], text: 'const' },
        },
        {
          ruleId: 'no-console',
          severity: 0,
          message: 'Disabled rule must be ignored.',
          line: 9,
          column: 1,
        },
      ],
    },
  ]);
  const eslintOut = AnalyzerRegistry.parseExternalJsonOutputWithValidation(
    getEngine('eslint-analyzer'),
    eslintFixture,
    TEST_SCOPE,
    '9.12.0'
  );
  assert.equal(eslintOut.validSchema, true);
  assert.equal(eslintOut.findings.length, 2, 'ESLint severity 0 must be ignored');
  assert.equal(eslintOut.findings[0]!.severity, 'HIGH');
  assert.equal(eslintOut.findings[0]!.category, 'SAST');
  assert.equal(eslintOut.findings[0]!.columnStart, 35);
  assert.equal(eslintOut.findings[0]!.validationStatus, 'UNVERIFIED');
  assert.equal(eslintOut.findings[1]!.severity, 'MEDIUM');
  assert.match(eslintOut.findings[1]!.remediation, /eslint --fix/i);

  const eslintInvalid = AnalyzerRegistry.parseExternalJsonOutputWithValidation(
    getEngine('eslint-analyzer'),
    JSON.stringify([{ wrongKey: true }]),
    TEST_SCOPE,
    '9.12.0'
  );
  assert.equal(eslintInvalid.validSchema, false);

  // 3. Ruff JSON
  const ruffFixture = JSON.stringify([
    {
      code: 'S602',
      message: 'subprocess call with shell=True identified',
      filename: 'src/query.py',
      location: { row: 2, column: 1 },
      end_location: { row: 2, column: 44 },
      fix: { message: 'Use shell=False with list arguments' },
    },
    {
      code: 'F401',
      message: 'unused import',
      filename: 'src/query.py',
      location: { row: 1, column: 8 },
    },
  ]);
  const ruffOut = AnalyzerRegistry.parseExternalJsonOutputWithValidation(
    getEngine('ruff-python'),
    ruffFixture,
    TEST_SCOPE,
    '0.6.9'
  );
  assert.equal(ruffOut.validSchema, true);
  assert.equal(ruffOut.findings.length, 2);
  assert.equal(ruffOut.findings[0]!.severity, 'HIGH');
  assert.equal(ruffOut.findings[0]!.category, 'SAST');
  assert.equal(ruffOut.findings[0]!.validationStatus, 'UNVERIFIED');
  assert.equal(ruffOut.findings[1]!.severity, 'MEDIUM');

  // 4. Bandit JSON
  const banditFixture = JSON.stringify({
    results: [
      {
        test_id: 'B602',
        test_name: 'subprocess_popen_with_shell_equals_true',
        issue_text: 'subprocess call with shell=True identified, security issue.',
        issue_severity: 'HIGH',
        issue_confidence: 'HIGH',
        issue_cwe: { id: 78 },
        filename: 'src/query.py',
        line_number: 2,
        line_range: [2, 3],
        code: 'subprocess.Popen(user_cmd, shell=True)',
      },
    ],
  });
  const banditOut = AnalyzerRegistry.parseExternalJsonOutputWithValidation(
    getEngine('bandit-python'),
    banditFixture,
    TEST_SCOPE,
    '1.7.9'
  );
  assert.equal(banditOut.validSchema, true);
  assert.equal(banditOut.findings.length, 1);
  assert.equal(banditOut.findings[0]!.originalRuleId, 'B602');
  assert.equal(banditOut.findings[0]!.cwe, 'CWE-78');
  assert.equal(banditOut.findings[0]!.endLineNumber, 3);
  assert.equal(banditOut.findings[0]!.validationStatus, 'UNVERIFIED');

  // 5. Semgrep & Gitleaks strict schema validation
  const semgrepBad = AnalyzerRegistry.parseExternalJsonOutputWithValidation(
    getEngine('semgrep-opengrep'),
    JSON.stringify({ results: [{ missingRequiredFields: true }] }),
    TEST_SCOPE,
    '1.90.0'
  );
  assert.equal(semgrepBad.validSchema, false);

  const gitleaksBad = AnalyzerRegistry.parseExternalJsonOutputWithValidation(
    getEngine('gitleaks-secrets'),
    JSON.stringify([{ invalid: 123 }]),
    TEST_SCOPE,
    '8.18.4'
  );
  assert.equal(gitleaksBad.validSchema, false);

  const gitleaksOk = AnalyzerRegistry.parseExternalJsonOutputWithValidation(
    getEngine('gitleaks-secrets'),
    JSON.stringify([
      {
        RuleID: 'generic-api-key',
        Description: 'Generic API Key',
        File: 'src/app.ts',
        StartLine: 1,
        EndLine: 1,
        Match: 'api_key="REDACTED"',
      },
    ]),
    TEST_SCOPE,
    '8.18.4'
  );
  assert.equal(gitleaksOk.validSchema, true);
  assert.equal(gitleaksOk.findings.length, 1);
  assert.equal(gitleaksOk.findings[0]!.validationStatus, 'UNVERIFIED');
});

test('CodeQL lifecycle helper detects primary language and constructs full database create + analyze SARIF commands', () => {
  const lang = detectCodeQlLanguage({
    'src/a.ts': 'export const a = 1;',
    'src/b.tsx': 'export const b = 2;',
    'scripts/c.py': 'print(1)',
  });
  assert.equal(lang, 'javascript-typescript');
  const plan = buildCodeQlLifecycleCommands('/tmp/src', lang, '/tmp/db', '/tmp/out.sarif');
  assert.ok(plan.databaseCreateArgs.includes('database'));
  assert.ok(plan.databaseCreateArgs.includes('create'));
  assert.ok(plan.databaseCreateArgs.includes('--language=javascript-typescript'));
  assert.ok(plan.databaseAnalyzeArgs.includes('--format=sarifv2.1.0'));
  assert.ok(plan.databaseAnalyzeArgs.includes('--output=/tmp/out.sarif'));
});
