import test from 'node:test';
import assert from 'node:assert/strict';
import { ParserRegistry } from './ParserRegistry';
import { TaintAnalyzer } from './TaintAnalyzer';
import { SbomGenerator } from './sca/SbomGenerator';
import { ScaCorrelator } from './sca/ScaCorrelator';
import { CoverageReportParser } from '../execution/CoverageReportParser';
import type { Software } from '../types/benchmark';

test('ParserRegistry parses TypeScript, Python, Java and SQL with real AST metrics and functions', () => {
  const tsAst = ParserRegistry.parseFile(
    'src/math.ts',
    [
      'export function classify(x: number): string {',
      '  if (x > 10 && x < 20) { return "mid"; }',
      '  return "other";',
      '}',
    ].join('\n')
  );
  assert.equal(tsAst.language, 'TypeScript');
  assert.equal(tsAst.astParsed, true);
  assert.equal(tsAst.functions.length, 1);
  assert.ok(tsAst.cyclomaticComplexity >= 2);

  const pyAst = ParserRegistry.parseFile(
    'app/calc.py',
    'def run_calc(user_expr):\n    return eval(user_expr)\n'
  );
  assert.equal(pyAst.language, 'Python');
  assert.equal(pyAst.astParsed, true);
  assert.ok(pyAst.issues.some((i) => i.cwe === 'CWE-95'));

  const sqlAst = ParserRegistry.parseFile(
    'db/init.sql',
    'CREATE TABLE users (id INT PRIMARY KEY, email VARCHAR(255));\n'
  );
  assert.equal(sqlAst.language, 'SQL');
  assert.equal(sqlAst.astParsed, true);
});

test('TaintAnalyzer detects cross-file Controller -> Repository SQLi and stays clean on parameterized Prepared Statement', () => {
  const vulnerableFiles = {
    'src/controller/searchCtrl.ts': [
      'import { runRawQuery } from "../db/searchRepo";',
      'export function handleSearch(userQuery: string, db: any) {',
      '  const sanitizedInput = userQuery.trim();',
      '  return runRawQuery(sanitizedInput, db);',
      '}',
    ].join('\n'),
    'src/db/searchRepo.ts': [
      'export function runRawQuery(filter: string, db: any) {',
      '  const sql = "SELECT id, name FROM users WHERE name = \'" + filter + "\'";',
      '  return db.query(sql);',
      '}',
    ].join('\n'),
  };

  const vulnAsts = Object.entries(vulnerableFiles).map(([fp, content]) =>
    ParserRegistry.parseFile(fp, content)
  );
  const vulnTaints = TaintAnalyzer.analyzeFlows(vulnAsts, vulnerableFiles);
  assert.ok(vulnTaints.some((i) => i.cwe === 'CWE-89'));

  const safeFiles = {
    'src/db/safeRepo.ts': [
      'export function runSafeQuery(filter: string, db: any) {',
      '  const sql = "SELECT id, name FROM users WHERE name = ?";',
      '  return db.query(sql, [filter]);',
      '}',
    ].join('\n'),
  };
  const safeAsts = Object.entries(safeFiles).map(([fp, content]) =>
    ParserRegistry.parseFile(fp, content)
  );
  const safeTaints = TaintAnalyzer.analyzeFlows(safeAsts, safeFiles);
  assert.equal(safeTaints.filter((i) => i.cwe === 'CWE-89').length, 0);
});

test('SbomGenerator produces CycloneDX 1.5 and SPDX 2.3 with SHA-256 and ScaCorrelator flags CVE/GHSA/EPSS', () => {
  const sw: Software = {
    id: 'sw-sbom-test',
    projectId: 'proj-sbom',
    name: 'SBOM Test App',
    vendor: 'WinHood QA',
    description: 'Dependency audit test',
    category: 'Backend',
    version: '1.0.0',
    languages: ['TypeScript'],
    architecture: 'Service',
    operatingSystem: 'Linux',
    distributionModel: 'API',
    licenseType: 'MIT',
    officialUrl: '',
    repositoryUrl: '',
    documentationUrl: '',
    owner: 'QA',
    notes: '',
    sourceType: 'LOCAL_UPLOAD',
    commitHash: 'abc123',
    packageSha256: '0'.repeat(64),
    createdAt: new Date().toISOString(),
    inventory: {
      totalFiles: 2,
      eligibleFiles: 1,
      totalLinesOfCode: 10,
      totalSizeBytes: 500,
      languageBreakdown: { JSON: 10 },
      files: [],
      isolatedStoragePath: '/tmp/sbom',
      verifiedIntegrity: true,
    },
    sourceFilesContent: {
      'package.json': JSON.stringify({
        name: 'sbom-test',
        version: '1.0.0',
        dependencies: {
          jsonwebtoken: '8.5.1',
        },
      }),
      'package-lock.json': JSON.stringify({
        name: 'sbom-test',
        lockfileVersion: 3,
        packages: {
          '': { name: 'sbom-test', version: '1.0.0' },
          'node_modules/jsonwebtoken': { version: '8.5.1', license: 'MIT' },
          'node_modules/lodash': { version: '4.17.19', license: 'MIT' },
        },
      }),
    },
  };

  const sbom = SbomGenerator.generateFromSoftware(sw);
  assert.equal(sbom.cyclonedx15Json.bomFormat, 'CycloneDX');
  assert.equal(sbom.cyclonedx15Json.specVersion, '1.5');
  assert.equal(sbom.spdx23Json.spdxVersion, 'SPDX-2.3');
  assert.equal(sbom.cyclonedxSha256.length, 64);
  assert.equal(sbom.spdxSha256.length, 64);
  assert.ok(sbom.directCount >= 1);
  assert.ok(sbom.transitiveCount >= 1);

  const { correlations } = ScaCorrelator.correlateSbom({ software: sw, sbom, runId: 'run-sca-1' });
  assert.ok(correlations.some((c) => c.cveId === 'CVE-2022-23529'));
  assert.ok(correlations.some((c) => c.cveId === 'CVE-2021-23337'));
});

test('CoverageReportParser parses LCOV, JaCoCo XML, Cobertura XML and Istanbul JSON accurately and returns NOT_MEASURED when absent', () => {
  const missing = CoverageReportParser.parseFromFilesMap({
    'src/index.ts': 'export const x = 1;',
    'tests/index.test.ts': 'export const ok = true;',
  });
  assert.equal(missing.found, false);
  assert.equal(missing.state, 'NOT_MEASURED');
  assert.equal(missing.lineCoveragePercent, null);

  const lcov = CoverageReportParser.parseFromFilesMap({
    'coverage/lcov.info': 'TN:\nSF:src/a.ts\nLF:20\nLH:16\nBRF:4\nBRH:3\nend_of_record\n',
  });
  assert.equal(lcov.found, true);
  assert.equal(lcov.format, 'LCOV');
  assert.equal(lcov.lineCoveragePercent, 80);
  assert.equal(lcov.state, 'MEASURED');

  const jacoco = CoverageReportParser.parseFromFilesMap({
    'target/jacoco.xml': '<report name="app"><counter type="LINE" missed="2" covered="8"/></report>',
  });
  assert.equal(jacoco.format, 'JACOCO_XML');
  assert.equal(jacoco.lineCoveragePercent, 80);

  const cobertura = CoverageReportParser.parseFromFilesMap({
    'coverage/cobertura.xml': '<coverage line-rate="0.75" branch-rate="0.50"></coverage>',
  });
  assert.equal(cobertura.format, 'COBERTURA_XML');
  assert.equal(cobertura.lineCoveragePercent, 75);

  const istanbul = CoverageReportParser.parseFromFilesMap({
    'coverage/coverage-final.json': JSON.stringify({
      'src/a.ts': {
        statementMap: { '0': {}, '1': {} },
        s: { '0': 1, '1': 0 },
      },
    }),
  });
  assert.equal(istanbul.format, 'ISTANBUL_JSON');
  assert.equal(istanbul.lineCoveragePercent, 50);

  // Cobertura without lines-valid must NOT fabricate line counts (linesFound === null)
  const coberturaOnlyRate = CoverageReportParser.parseFromFilesMap({
    'coverage/cobertura.xml': '<coverage line-rate="0.75"></coverage>',
  });
  assert.equal(coberturaOnlyRate.state, 'MEASURED');
  assert.equal(coberturaOnlyRate.lineCoveragePercent, 75);
  assert.equal(coberturaOnlyRate.linesFound, null);
  assert.equal(coberturaOnlyRate.linesHit, null);

  // Duplicate SF entries across aggregated LCOV blocks deduplicated accurately
  const dupLcov = CoverageReportParser.parseFromFilesMap({
    'coverage/lcov.info': [
      'SF:src/dup.ts',
      'DA:1,1',
      'DA:2,0',
      'end_of_record',
      'SF:src/dup.ts',
      'DA:1,3',
      'DA:2,2',
      'end_of_record',
    ].join('\n'),
  });
  assert.equal(dupLcov.state, 'MEASURED');
  assert.equal(dupLcov.linesFound, 2);
  assert.equal(dupLcov.linesHit, 2);
  assert.equal(dupLcov.lineCoveragePercent, 100);
});

test('TaintAnalyzer enforces sink-aware sanitization (encodeURIComponent/parseInt/escapeHtml/basename) and 2-hop interprocedural flows', () => {
  // 1. encodeURIComponent does NOT neutralize SQLi (CWE-89)
  const urlEncodedSqlFiles = {
    'src/api/search.ts': [
      'export function searchUser(userQuery: string, db: any) {',
      '  const encoded = encodeURIComponent(userQuery);',
      '  const sql = "SELECT * FROM users WHERE q = \'" + encoded + "\'";',
      '  return db.query(sql);',
      '}',
    ].join('\n'),
  };
  const encAst = Object.entries(urlEncodedSqlFiles).map(([p, c]) => ParserRegistry.parseFile(p, c));
  const encTaints = TaintAnalyzer.analyzeFlows(encAst, urlEncodedSqlFiles);
  assert.ok(encTaints.some((i) => i.cwe === 'CWE-89'), 'encodeURIComponent must not clear SQLi taint');

  // 2. parseInt neutralizes numeric SQLi
  const numericSanitizedFiles = {
    'src/api/byId.ts': [
      'export function findById(userQuery: string, db: any) {',
      '  const numericId = parseInt(userQuery, 10);',
      '  return db.query("SELECT * FROM users WHERE id = " + numericId);',
      '}',
    ].join('\n'),
  };
  const numAst = Object.entries(numericSanitizedFiles).map(([p, c]) => ParserRegistry.parseFile(p, c));
  const numTaints = TaintAnalyzer.analyzeFlows(numAst, numericSanitizedFiles);
  assert.equal(numTaints.filter((i) => i.cwe === 'CWE-89').length, 0);

  // 3. escapeHtml sanitizes XSS (CWE-79)
  const escapedXssFiles = {
    'src/web/greet.ts': [
      'declare function escapeHtml(v: string): string;',
      'declare function renderHtml(v: string): void;',
      'export function greetUser(userName: string) {',
      '  const safe = escapeHtml(userName);',
      '  return renderHtml(safe);',
      '}',
    ].join('\n'),
  };
  const xssAst = Object.entries(escapedXssFiles).map(([p, c]) => ParserRegistry.parseFile(p, c));
  const xssTaints = TaintAnalyzer.analyzeFlows(xssAst, escapedXssFiles);
  assert.equal(xssTaints.filter((i) => i.cwe === 'CWE-79').length, 0);

  // 4. path.basename sanitizes Path Traversal (CWE-22)
  const safePathFiles = {
    'src/files/readDoc.ts': [
      'import path from "node:path";',
      'import fs from "node:fs";',
      'export function readDoc(fileName: string) {',
      '  const safeName = path.basename(fileName);',
      '  return fs.readFileSync(safeName, "utf8");',
      '}',
    ].join('\n'),
  };
  const pathAst = Object.entries(safePathFiles).map(([p, c]) => ParserRegistry.parseFile(p, c));
  const pathTaints = TaintAnalyzer.analyzeFlows(pathAst, safePathFiles);
  assert.equal(pathTaints.filter((i) => i.cwe === 'CWE-22').length, 0);

  // 5. Two-hop interprocedural propagation (controller -> service -> repo -> SQLi sink)
  const twoHopFiles = {
    'src/ctrl.ts': [
      'import { dispatchLookup } from "./svc";',
      'export function apiHandler(userQuery: string, db: any) {',
      '  const term = userQuery.trim();',
      '  return dispatchLookup(term, db);',
      '}',
    ].join('\n'),
    'src/svc.ts': [
      'import { runRepoQuery } from "./repo";',
      'export function dispatchLookup(filter: string, db: any) {',
      '  return runRepoQuery(filter, db);',
      '}',
    ].join('\n'),
    'src/repo.ts': [
      'export function runRepoQuery(rawFilter: string, db: any) {',
      '  return db.query("SELECT * FROM items WHERE label = \'" + rawFilter + "\'");',
      '}',
    ].join('\n'),
  };
  const twoHopAst = Object.entries(twoHopFiles).map(([p, c]) => ParserRegistry.parseFile(p, c));
  const twoHopTaints = TaintAnalyzer.analyzeFlows(twoHopAst, twoHopFiles);
  assert.ok(twoHopTaints.some((i) => i.cwe === 'CWE-89'));
});

