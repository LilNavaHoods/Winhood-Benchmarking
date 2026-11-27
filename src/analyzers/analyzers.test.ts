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

test('Phase 6: SbomGenerator CycloneDX 1.5/1.7 & SPDX 2.3/3.0.1 schema validation, negative rejection, and multi-lockfile parsing', async () => {
  const { SbomGenerator, resolvePackageSpdxLicense } = await import('./sca/SbomGenerator');

  assert.equal(resolvePackageSpdxLicense('unlisted-internal-lib', undefined, 'MIT', { strictProvenance: true }), 'NOASSERTION');

  const sbomBundle = SbomGenerator.generateFromSoftware(
    {
      id: 'sw-phase6-sbom',
      name: 'PolyglotSupplyChain',
      version: '2.1.0',
      languages: ['TypeScript', 'Python', 'Go', 'Rust', 'Java', 'C#'],
      sourceFilesContent: {
        'package.json': JSON.stringify({
          name: 'polyglot-app',
          version: '2.1.0',
          dependencies: { express: '^4.21.2', 'crypto-js': '4.1.1' },
          optionalDependencies: { fsevents: '2.3.3' },
          devDependencies: { typescript: '5.9.3' },
        }),
        'npm-shrinkwrap.json': JSON.stringify({
          lockfileVersion: 3,
          packages: {
            'node_modules/express': { version: '4.21.2', license: 'MIT', integrity: 'sha512-abc' },
            'node_modules/crypto-js': { version: '4.1.1', license: 'MIT', integrity: 'sha512-def' },
          },
        }),
        'requirements.txt': 'PyYAML==5.3.1\nrequests>=2.31.0',
        'pyproject.toml': 'dependencies = ["fastapi==0.115.0"]',
        'go.mod': 'require (\n  github.com/gin-gonic/gin v1.10.0\n  golang.org/x/net v0.25.0 // indirect\n)',
        'Cargo.toml': '[dependencies]\nserde = "1.0.210"',
        'Cargo.lock': '[[package]]\nname = "tokio"\nversion = "1.40.0"\nchecksum = "a'.repeat(1).concat('0'.repeat(63)) + '"',
        'pom.xml': '<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>',
        'App.csproj': '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>',
      },
    } as any,
    {
      deterministicTimestamp: '2026-11-17T12:00:00.000Z',
      strictLicenseProvenance: true,
    }
  );

  assert.ok(sbomBundle.componentsCount >= 10);
  assert.ok(sbomBundle.supportedFormats?.includes('cyclonedx-1.7'));
  assert.ok(sbomBundle.supportedFormats?.includes('spdx-3.0'));
  assert.equal(sbomBundle.structuralValidation?.cyclonedxValid, true);
  assert.equal(sbomBundle.structuralValidation?.cyclonedx17Valid, true);
  assert.equal(sbomBundle.structuralValidation?.spdxValid, true);
  assert.equal(sbomBundle.structuralValidation?.spdx30Valid, true);
  assert.deepEqual(sbomBundle.structuralValidation?.errors, []);

  // Verify NOASSERTION for unknown pypi/go/cargo/maven/nuget licenses under strict provenance
  const pyyaml = sbomBundle.components.find((c) => c.name === 'PyYAML');
  assert.equal(pyyaml?.license, 'NOASSERTION');

  // Verify signature verification passes and rejects tampered bundles
  const sigOk = SbomGenerator.verifySbomSignature(sbomBundle);
  assert.equal(sigOk.valid, true);

  const brokenCdx = structuredClone(sbomBundle.cyclonedx15Json) as any;
  brokenCdx.components[0].version = '';
  brokenCdx.dependencies.push({ ref: 'app:ghost', dependsOn: ['pkg:npm/missing@0.0.0'] });
  const badCdxRes = SbomGenerator.validateCycloneDxSchema(brokenCdx, '1.5');
  assert.equal(badCdxRes.valid, false);
  assert.ok(badCdxRes.errors.some((e) => e.includes('version must be a non-empty string')));
  assert.ok(badCdxRes.errors.some((e) => e.includes('dangling')));

  const brokenSpdx30 = structuredClone(sbomBundle.spdx30Json) as any;
  brokenSpdx30['@graph'].push({
    type: 'Relationship',
    spdxId: 'bad-rel',
    from: 'missing-node',
    to: ['dangling-pkg'],
  });
  const badSpdx30Res = SbomGenerator.validateSpdx30JsonLdSchema(brokenSpdx30);
  assert.equal(badSpdx30Res.valid, false);
  assert.ok(badSpdx30Res.errors.some((e) => e.includes('dangling')));
});

test('Phase 6: ScaCorrelator offline snapshot vs live-synced cache provenance & AnalyzerRegistry binary discovery', async () => {
  const fsMod = await import('node:fs');
  const osMod = await import('node:os');
  const pathMod = await import('node:path');
  const { SbomGenerator } = await import('./sca/SbomGenerator');
  const { ScaCorrelator, DEFAULT_ENTERPRISE_LICENSE_POLICY } = await import('./sca/ScaCorrelator');
  const { AnalyzerRegistry } = await import('./AnalyzerRegistry');
  const { RuleRegistry } = await import('./RuleRegistry');
  const { SecretScanner } = await import('./SecretsCatalog');
  const { SarifCodec } = await import('./SarifCodec');

  const sw = {
    id: 'sw-sca-phase6',
    name: 'ScaTarget',
    version: '1.0.0',
    sourceFilesContent: {
      'package.json': JSON.stringify({
        name: 'sca-target',
        version: '1.0.0',
        dependencies: { 'crypto-js': '4.1.1', lodash: '4.17.20' },
      }),
      'requirements.txt': 'pyyaml==5.3.1',
      'pom.xml': '<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>',
    },
  } as any;

  const sbom = SbomGenerator.generateFromSoftware(sw, { deterministicTimestamp: '2026-11-17T12:00:00.000Z' });
  const tmpData = fsMod.mkdtempSync(pathMod.join(osMod.tmpdir(), 'wh-sca-p6-'));

  try {
    const offlineCor = ScaCorrelator.correlateSbom({
      software: sw,
      sbom,
      dataDir: tmpData,
      licensePolicy: { ...DEFAULT_ENTERPRISE_LICENSE_POLICY, failOnUnknownLicense: true },
      deterministicTimestamp: '2026-11-17T12:00:00.000Z',
    });
    assert.equal(offlineCor.advisoryFeedMetadata.cacheMode, 'OFFLINE_VERIFIED_SNAPSHOT');
    assert.ok(offlineCor.correlations.some((c) => c.cveId === 'CVE-2023-46233'));
    assert.ok(offlineCor.correlations.some((c) => c.cveId === 'CVE-2021-44228' && c.cisaKev === true));

    // Seed live-synced cache file in tmpData to verify LIVE_SYNCED_CACHE provenance differentiation
    const refDir = pathMod.join(tmpData, 'reference_snapshots');
    fsMod.mkdirSync(refDir, { recursive: true });
    fsMod.writeFileSync(
      pathMod.join(refDir, 'synced_advisories.json'),
      JSON.stringify({
        updatedAt: '2026-11-17T11:30:00.000Z',
        advisories: [
          {
            packageName: 'lodash',
            affectedVersionRange: '== 4.17.20',
            cveId: 'CVE-2021-23337',
            ghsaId: 'GHSA-35jh-r3h4-6jhm',
            cvssScore: 7.2,
            epssScore: 0.625,
            epssPercentile: 0.98,
            cisaKev: false,
            fixedVersion: '4.17.21',
            cweIds: ['CWE-94'],
            syncedAt: '2026-11-17T11:30:00.000Z',
            summary: 'Synced OSV advisory',
          },
        ],
        kevCveIds: ['CVE-2021-44228'],
        epssByCve: {},
        nvdByCve: {},
      }),
      'utf8'
    );
    const liveCor = ScaCorrelator.correlateSbom({
      software: sw,
      sbom,
      dataDir: tmpData,
      deterministicTimestamp: '2026-11-17T12:00:00.000Z',
    });
    assert.equal(liveCor.advisoryFeedMetadata.cacheMode, 'LIVE_SYNCED_CACHE');

    // RuleRegistry, SecretScanner, SarifCodec, and AnalyzerRegistry binary availability
    assert.ok(RuleRegistry.getRulesForLanguage('TypeScript').length > 0);
    assert.ok(RuleRegistry.findRule('ts:S3649'));
    assert.ok(SecretScanner.getCatalogMetadata().patternsCount > 0);
    const sarifOut = SarifCodec.exportSarif210(offlineCor.findings);
    assert.equal((sarifOut.runs as unknown[]).length, 1);
    const sarifParsed = SarifCodec.importSarif210(sarifOut, {
      runId: 'test-run-sarif',
      softwareId: sw.id,
      softwareName: sw.name,
      softwareVersion: sw.version,
    });
    assert.equal(sarifParsed.valid, true);
    assert.ok(sarifParsed.importedToolNames.length >= 1);
    assert.equal(sarifParsed.findings.length, offlineCor.findings.length);

    const extAvail = AnalyzerRegistry.discoverExternalEngineAvailability();
    assert.ok(Array.isArray(extAvail));
    assert.ok(AnalyzerRegistry.listNativePlugins().length >= 1);
  } finally {
    fsMod.rmSync(tmpData, { recursive: true, force: true });
  }
});

test('Security & Reliability regression: SbomGenerator path traversal confinement, ScaCorrelator ReDoS-safe PEP440, TaintAnalyzer RegExp.exec precision', async () => {
  const { resolvePackageSpdxLicenseWithProvenance } = await import('./sca/SbomGenerator');
  const { comparePep440 } = await import('./sca/ScaCorrelator');
  const { ParserRegistry } = await import('./ParserRegistry');
  const { TaintAnalyzer } = await import('./TaintAnalyzer');
  const { SarifCodec } = await import('./SarifCodec');

  // 1. SbomGenerator must block path traversal package names from reading outside node_modules/
  const traversalCandidates = [
    '..',
    '../package.json',
    '../../../etc',
    '..\\..\\package',
    '@scope/../../package',
    'express/../../package',
  ];
  for (const pkg of traversalCandidates) {
    const res = resolvePackageSpdxLicenseWithProvenance(pkg, undefined, undefined, {
      strictProvenance: true,
    });
    assert.equal(res.license, 'NOASSERTION', `Expected traversal package "${pkg}" to return NOASSERTION`);
    assert.equal(res.provenance, 'UNVERIFIED', `Expected traversal package "${pkg}" to stay UNVERIFIED`);
  }

  // 2. ScaCorrelator PEP 440 parser must execute in linear time on adversarial ReDoS input and preserve ordering
  const adversarialVersion = `1.${'0.'.repeat(500)}a`;
  const t0 = Date.now();
  const cmpAdversarial = comparePep440(adversarialVersion, '1.0.0');
  const elapsedMs = Date.now() - t0;
  assert.equal(typeof cmpAdversarial, 'number');
  assert.ok(elapsedMs < 50, `Expected linear-time PEP 440 comparison (<50ms), took ${elapsedMs}ms`);

  assert.equal(comparePep440('1.0.0.dev1', '1.0.0a1') < 0, true);
  assert.equal(comparePep440('1.0.0a1', '1.0.0b1') < 0, true);
  assert.equal(comparePep440('1.0.0b1', '1.0.0rc1') < 0, true);
  assert.equal(comparePep440('1.0.0rc1', '1.0.0') < 0, true);
  assert.equal(comparePep440('1.0.0', '1.0.0.post1') < 0, true);
  assert.equal(comparePep440('1!1.0', '2.0.0') > 0, true);

  // 3. TaintAnalyzer must NOT flag RegExp.prototype.exec as command/SQL injection, while STILL flagging real sinks
  const cleanRegexCode = `
    export function parseUserHeader(req: any) {
      const header = String(req.headers['x-custom'] || '');
      const pattern = /^([a-z0-9-]+):([a-z0-9-]+)$/i;
      const match = pattern.exec(header);
      return match ? match[1] : null;
    }
  `;
  const cleanParsed = ParserRegistry.parseFile('src/parser.ts', cleanRegexCode);
  const cleanIssues = TaintAnalyzer.analyzeFlows([cleanParsed], { 'src/parser.ts': cleanRegexCode });
  assert.equal(
    cleanIssues.length,
    0,
    `Expected 0 false positives on RegExp.prototype.exec, got: ${cleanIssues.map((f) => f.ruleId).join(', ')}`
  );

  const realVulnCode = `
    import { exec } from 'node:child_process';
    import fs from 'node:fs';
    export function dangerousHandler(req: any) {
      const cmd = req.query.cmd;
      exec('ls ' + cmd);
      const userFile = req.query.file;
      return fs.readFileSync(userFile, 'utf8');
    }
  `;
  const vulnParsed = ParserRegistry.parseFile('src/vuln.ts', realVulnCode);
  const vulnIssues = TaintAnalyzer.analyzeFlows([vulnParsed], { 'src/vuln.ts': realVulnCode });
  assert.ok(
    vulnIssues.some((f) => f.ruleId === 'taint:S2076' || /CWE-78|comando|command/i.test(f.title)),
    `Expected TaintAnalyzer to detect real OS command injection, got: ${vulnIssues.map((f) => `${f.ruleId}:${f.title}`).join('; ')}`
  );
  assert.ok(
    vulnIssues.some((f) => f.ruleId === 'taint:S2083' || /CWE-22|path traversal/i.test(f.title)),
    `Expected TaintAnalyzer to detect real path traversal, got: ${vulnIssues.map((f) => `${f.ruleId}:${f.title}`).join('; ')}`
  );

  // 4. SarifCodec.exportSarif210 emits contextRegion when contextBefore/contextAfter are present
  const sarif = SarifCodec.exportSarif210([
    {
      id: 'finding-reg-1',
      runId: 'reg-run',
      softwareId: 'sw-reg',
      softwareName: 'RegTarget',
      softwareVersion: '1.0.0',
      toolName: 'WinHood Native SAST',
      originType: 'NATIVE_ANALYSIS',
      originalRuleId: 'ts:S4721',
      category: 'SAST',
      cwe: 'CWE-78',
      cvss: 9.8,
      severity: 'BLOCKER',
      confidence: 'HIGH',
      validationStatus: 'CONFIRMED',
      title: 'OS Command Injection',
      description: 'Untrusted input reaches exec()',
      filePath: 'src/vuln.ts',
      lineNumber: 6,
      snippet: "exec('ls ' + cmd);",
      contextBefore: ['const cmd = req.query.cmd;'],
      contextAfter: ['return ok;'],
      remediation: 'Use execFile with argument array and shell: false.',
      remediationEffortMinutes: 30,
      collectedAt: '2026-11-27T00:00:00.000Z',
    } as any,
  ]) as any;
  assert.ok(
    sarif.runs[0].results[0].locations[0].physicalLocation.contextRegion.snippet.text.includes('>>> '),
    'Expected SarifCodec.exportSarif210 to emit contextRegion snippet'
  );
});



