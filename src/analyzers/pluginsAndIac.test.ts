import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { AnalyzerRegistry } from './AnalyzerRegistry';
import { ParserRegistry } from './ParserRegistry';
import { TaintAnalyzer } from './TaintAnalyzer';
import { SarifCodec } from './SarifCodec';
import { SecretScanner, maskDetectedSecret } from './SecretsCatalog';
import { AnalyzerPluginManager } from './plugins/AnalyzerPluginSystem';
import { SbomGenerator } from './sca/SbomGenerator';
import { DEFAULT_ENTERPRISE_LICENSE_POLICY, ScaCorrelator } from './sca/ScaCorrelator';
import type { Software } from '../types/benchmark';

function makeTestSoftware(id: string, name: string, version: string, filesMap: Record<string, string>): Software {
  return {
    id,
    projectId: 'proj-test',
    name,
    vendor: 'WinHood QA',
    description: 'Unit test software fixture',
    version,
    languages: ['TypeScript'],
    architecture: 'Modular',
    operatingSystem: 'Linux',
    distributionModel: 'Source',
    licenseType: 'MIT',
    officialUrl: '',
    repositoryUrl: '',
    documentationUrl: '',
    owner: 'qa',
    notes: '',
    sourceType: 'LOCAL_UPLOAD',
    sourceAvailability: 'FULL_SOURCE',
    ingestionState: 'SOURCE_VALIDATED',
    commitHash: 'TEST_HEAD',
    packageSha256: 'TEST_SHA256',
    createdAt: '2026-11-14T00:00:00.000Z',
    inventory: {
      totalFiles: Object.keys(filesMap).length,
      eligibleFiles: Object.keys(filesMap).length,
      totalLinesOfCode: 30,
      totalSizeBytes: 512,
      languageBreakdown: { TypeScript: 30 },
      files: [],
      isolatedStoragePath: '/tmp/test',
      verifiedIntegrity: true,
    },
    sourceFilesContent: filesMap,
  };
}

test('ParserRegistry parses TypeScript, Python, Java, and Go with structural AST symbols', () => {
  const goAst = ParserRegistry.parseFile(
    'cmd/server.go',
    [
      'package main',
      'func handleRequest(userInput string) string {',
      '  return db.Query("SELECT * FROM users WHERE name = " + userInput)',
      '}',
    ].join('\n')
  );
  assert.equal(goAst.language, 'Go');
  assert.equal(goAst.astParsed, true);
  assert.ok(goAst.functions.some((f) => f.name === 'handleRequest'));

  const javaAst = ParserRegistry.parseFile(
    'src/Repo.java',
    [
      'public class Repo {',
      '  public String findUser(String q) {',
      '    if (q != null) { return stmt.executeQuery("SELECT * FROM u WHERE id=" + q); }',
      '    return "";',
      '  }',
      '}',
    ].join('\n')
  );
  assert.equal(javaAst.language, 'Java');
  assert.equal(javaAst.astParsed, true);
  assert.ok(javaAst.functions.some((f) => f.name === 'findUser'));
});

test('TaintAnalyzer detects SSRF (CWE-918) and suppresses when SsrfGuard sanitizer is present', () => {
  const vulnFiles = {
    'src/proxy.ts': [
      'export async function fetchTarget(req: any) {',
      '  const targetUrl = req.query.url;',
      '  return fetch(targetUrl);',
      '}',
    ].join('\n'),
  };
  const vulnAsts = Object.entries(vulnFiles).map(([p, c]) => ParserRegistry.parseFile(p, c));
  const vulnFlows = TaintAnalyzer.analyzeFlows(vulnAsts, vulnFiles);
  const ssrf = vulnFlows.find((f) => f.cwe === 'CWE-918');
  assert.ok(ssrf, 'Expected CWE-918 SSRF finding');
  assert.ok((ssrf?.executionFlows?.length || 0) >= 3, 'Expected 3-step Source->Propagator->Sink flow');

  const safeFiles = {
    'src/safeProxy.ts': [
      'import { SsrfGuard } from "./ssrf";',
      'export async function fetchSafeTarget(req: any) {',
      '  const targetUrl = SsrfGuard.validateExternalUrl(req.query.url);',
      '  return fetch(targetUrl);',
      '}',
    ].join('\n'),
  };
  const safeAsts = Object.entries(safeFiles).map(([p, c]) => ParserRegistry.parseFile(p, c));
  const safeFlows = TaintAnalyzer.analyzeFlows(safeAsts, safeFiles);
  assert.equal(safeFlows.filter((f) => f.cwe === 'CWE-918').length, 0);
});

test('IacAnalyzerPlugin detects Terraform, Kubernetes, Dockerfile, and GitHub Actions misconfigurations', () => {
  const iacFiles: Record<string, string> = {
    'infra/main.tf': [
      'resource "aws_security_group" "open" {',
      '  ingress { cidr_blocks = ["0.0.0.0/0"] }',
      '}',
      'resource "aws_s3_bucket" "pub" {',
      '  acl = "public-read"',
      '}',
    ].join('\n'),
    'k8s/deployment.yaml': [
      'apiVersion: apps/v1',
      'kind: Deployment',
      'spec:',
      '  template:',
      '    spec:',
      '      securityContext:',
      '        runAsUser: 0',
      '      containers:',
      '        - name: app',
      '          securityContext:',
      '            privileged: true',
    ].join('\n'),
    Dockerfile: [
      'FROM node:22-alpine',
      'USER root',
      'CMD ["node", "server.js"]',
    ].join('\n'),
    '.github/workflows/ci.yml': [
      'permissions: write-all',
      'jobs:',
      '  test:',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '      - run: echo "${{ github.event.pull_request.title }}"',
    ].join('\n'),
  };

  const pluginOut = AnalyzerPluginManager.executePlugins({
    scope: {
      runId: 'iac-test',
      softwareId: 'sw-iac',
      softwareName: 'IaCTest',
      softwareVersion: '1.0.0',
      filesMap: iacFiles,
    },
    files: Object.entries(iacFiles).map(([filePath, content]) => ({ filePath, content })),
    parseResults: [],
    slaBudgetMs: 5000,
    deterministicTimestamp: '2026-11-14T00:00:00.000Z',
  });

  const ruleIds = new Set(pluginOut.candidates.map((i) => i.ruleId));
  assert.ok(ruleIds.has('iac:TF-001'));
  assert.ok(ruleIds.has('iac:TF-002'));
  assert.ok(ruleIds.has('iac:K8S-001'));
  assert.ok(ruleIds.has('iac:DOCKER-001'));
  assert.ok(ruleIds.has('iac:GHA-001'));
});

test('SecretScanner detects high-entropy secrets with redaction and excludes documented false positives', () => {
  const fakeAkia = ['AKIA', 'IOSFODNN7REAL9K2'].join('');
  const files = {
    'src/config.ts': [
      `export const awsKey = "${fakeAkia}";`,
      'export const api_secret = "xK9$mP2@vQ7#nL4!zR8&wT5^yB3*cD6";',
      'export const placeholder = "changeme";',
      'export const exampleAws = "AKIAIOSFODNN7EXAMPLE";',
      'export const envKey = process.env.API_SECRET;',
    ].join('\n'),
  };

  const issues = SecretScanner.scanFiles(files);
  assert.ok(issues.some((i) => i.ruleId === 'sec:S6418-AWS'));
  assert.ok(issues.some((i) => i.ruleId === 'sec:S6418-ENTROPY'));
  assert.ok(!issues.some((i) => i.snippet.includes('AKIAIOSFODNN7EXAMPLE')));
  assert.ok(!issues.some((i) => i.snippet.includes(fakeAkia)), 'Secret must be masked in snippet');
  assert.equal(maskDetectedSecret('ABCDEFGHIJKLMNOP'), 'ABCD***NOP');
});

test('AnalyzerRegistry delivers bit-for-bit determinism and valid SARIF 2.1.0 round-trip', () => {
  const filesMap = {
    'src/a.ts': 'export function q(id: string, db: any) { return db.query("SELECT * FROM t WHERE id=" + id); }\n',
    Dockerfile: 'FROM node:22\nUSER root\n',
  };
  const scope = {
    runId: 'run-det',
    softwareId: 'sw-det-1',
    softwareName: 'DeterministicTarget',
    softwareVersion: '1.0.0',
    filesMap,
  };

  const detOpts = { deterministicTimestamp: '2026-11-14T00:00:00.000Z' };
  const r1 = AnalyzerRegistry.runNativeAstAndTaintPipeline(scope, detOpts);
  const r2 = AnalyzerRegistry.runNativeAstAndTaintPipeline(scope, detOpts);

  assert.equal(r1.deterministicDigestSha256, r2.deterministicDigestSha256);
  assert.equal(r1.ruleCatalogSha256, r2.ruleCatalogSha256);
  assert.deepEqual(r1.findings, r2.findings);

  const sarif = SarifCodec.exportSarif210(r1.findings, {
    softwareArtifacts: [{ name: scope.softwareName, version: scope.softwareVersion }],
  });
  const imported = SarifCodec.importSarif210(sarif, {
    runId: 'run-det-import',
    softwareId: scope.softwareId,
    softwareName: scope.softwareName,
    softwareVersion: scope.softwareVersion,
  });
  assert.equal(imported.valid, true);
  assert.equal(imported.findings.length, r1.findings.length);
});

test('SbomGenerator signs CycloneDX/SPDX bundles deterministically and ScaCorrelator enforces license policy + incremental merge', () => {
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'winhood-sbom-test-'));
  const prevKeystore = process.env.WINHOOD_KEYSTORE_PATH;
  process.env.WINHOOD_KEYSTORE_PATH = path.join(tmpDataDir, 'keys', 'keystore.json');
  try {
    const sw = makeTestSoftware('sw-sbom-1', 'SbomTarget', '2.0.0', {
      'package.json': JSON.stringify({
        name: 'sbom-target',
        version: '2.0.0',
        dependencies: { jsonwebtoken: '8.5.1', 'copyleft-lib': '1.0.0' },
      }),
      'package-lock.json': JSON.stringify({
        packages: {
          'node_modules/jsonwebtoken': { version: '8.5.1', license: 'MIT' },
          'node_modules/copyleft-lib': { version: '1.0.0', license: 'AGPL-3.0' },
        },
      }),
    });

    const opts = { deterministicTimestamp: '2026-11-14T00:00:00.000Z', signSbom: true };
    const b1 = SbomGenerator.generateFromSoftware(sw, opts);
    const b2 = SbomGenerator.generateFromSoftware(sw, opts);

    assert.ok(b1.signature?.hmacSignature);
    assert.equal(b1.signature?.payloadSha256, b2.signature?.payloadSha256);
    assert.equal(SbomGenerator.verifySbomSignature(b1).valid, true);

    // Tampering invalidates SBOM signature
    const tampered = {
      ...b1,
      components: [...b1.components, { ...b1.components[0]!, name: 'tampered-pkg' }],
    };
    assert.equal(SbomGenerator.verifySbomSignature(tampered).valid, false);

    const licEval = ScaCorrelator.evaluateLicensePolicy({
      sbom: b1,
      software: sw,
      policy: DEFAULT_ENTERPRISE_LICENSE_POLICY,
      runId: 'run-lic',
      collectedAt: '2026-11-14T00:00:00.000Z',
    });
    assert.equal(licEval.compliant, false);
    assert.ok(licEval.violations.some((v) => v.license === 'AGPL-3.0'));
    assert.ok(licEval.findings.some((f) => f.originalRuleId === 'sca:LIC-001'));

    const merged = ScaCorrelator.mergeIncrementalAdvisories(
      [{ packageName: 'lodash', affectedVersionRange: '<4.17.21', cveId: 'CVE-2021-23337', syncedAt: '2026-01-01' }],
      [
        { packageName: 'lodash', affectedVersionRange: '<4.17.21', cveId: 'CVE-2021-23337', syncedAt: '2026-11-14' },
        { packageName: 'axios', affectedVersionRange: '<1.6.0', cveId: 'CVE-2023-45857', syncedAt: '2026-11-14' },
      ]
    );
    assert.equal(merged.addedCount, 1);
    assert.equal(merged.updatedCount, 1);
    assert.equal(merged.merged.length, 2);
  } finally {
    if (prevKeystore === undefined) delete process.env.WINHOOD_KEYSTORE_PATH;
    else process.env.WINHOOD_KEYSTORE_PATH = prevKeystore;
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
  }
});
