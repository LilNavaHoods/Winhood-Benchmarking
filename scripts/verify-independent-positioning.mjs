#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';

/**
 * Semantic Independent Positioning Verifier for WinHood Benchmarking.
 *
 * Rules:
 * - ALLOWS legitimate technical references to user-authorized optional integrations,
 *   privacy/consent disclosures (e.g. PrivacyAndTermsModal.tsx), API compatibility
 *   bridges, and neutral methodological comparisons.
 * - BLOCKS deceptive claims of commercial affiliation, official partnership,
 *   unverified third-party certification, or misidentification of WinHood as an
 *   official product of a third-party vendor (e.g. SonarSource, SonarQube, GitHub,
 *   Microsoft, OWASP, Snyk, Semgrep).
 */

const PROHIBITED_AFFILIATION_PATTERNS = [
  {
    id: 'FALSE_OFFICIAL_PARTNERSHIP',
    description: 'False claim of official commercial partnership or sponsorship with third-party vendor',
    regex: /\b(?:official(?:ly)?\s+(?:partner(?:ed)?\s+with|sponsored\s+by|affiliated\s+with)|parceir[oa]\s+oficial\s+d[aeo]|afiliad[oa]\s+oficial(?:mente)?\s+(?:a|com))\s+(?:Sonar(?:Source|Qube|Cloud)|GitHub|Microsoft|Snyk|Semgrep|Veracode|Checkmarx)\b/i,
  },
  {
    id: 'UNVERIFIED_THIRD_PARTY_CERTIFICATION',
    description: 'Unverified claim of official certification or endorsement by third-party authority',
    regex: /\b(?:officially\s+(?:certified|endorsed|accredited)\s+by|certificad[oa]\s+oficialmente\s+p(?:or|ela)|homologad[oa]\s+oficialmente\s+p(?:or|ela))\s+(?:Sonar(?:Source|Qube|Cloud)|OWASP|NIST|ISO|GitHub|Microsoft|Snyk)\b/i,
  },
  {
    id: 'MISIDENTIFICATION_AS_THIRD_PARTY_PRODUCT',
    description: 'Deceptive identification of WinHood as an official product, edition, or clone owned by a third party',
    regex: /\bWinHood\s+(?:is\s+an?\s+official\s+(?:Sonar(?:Source|Qube|Cloud)|GitHub|Microsoft)\s+product|[eé]\s+um\s+produto\s+oficial\s+d[aeo]\s+(?:Sonar(?:Source|Qube|Cloud)|GitHub|Microsoft)|by\s+SonarSource| powered\s+officially\s+by\s+Sonar(?:Source|Qube|Cloud))\b/i,
  },
];

const LEGITIMATE_CONTEXT_MARKERS = [
  /quando voc[eê] mesmo configura sua chave\/token e autoriza/i,
  /optional(?:\s+user-authorized)?\s+integration/i,
  /integra[cç][aã]o\s+opcional/i,
  /protocol\/API\s+compatibility/i,
  /compatibilidade\s+t[eé]cnica\s+de\s+API/i,
  /independent(?:e)?\s+benchmark/i,
];

/**
 * Evaluates a text snippet and returns structured positioning verification result.
 * @param {string} content
 * @param {string} [filePath]
 */
export function evaluatePositioningText(content, filePath = '<memory>') {
  const violations = [];
  const legitimateReferences = [];
  const lines = content.split(/\r?\n/);

  lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    for (const rule of PROHIBITED_AFFILIATION_PATTERNS) {
      if (rule.regex.test(line)) {
        violations.push({
          filePath,
          line: lineNum,
          ruleId: rule.id,
          description: rule.description,
          excerpt: line.trim().slice(0, 180),
        });
      }
    }

    if (/\b(?:SonarQube|SonarCloud|SonarSource)\b/i.test(line)) {
      const isViolatingLine = PROHIBITED_AFFILIATION_PATTERNS.some((r) => r.regex.test(line));
      if (!isViolatingLine) {
        const matchedMarker = LEGITIMATE_CONTEXT_MARKERS.some((m) => m.test(line) || m.test(content));
        legitimateReferences.push({
          filePath,
          line: lineNum,
          contextualized: matchedMarker,
          excerpt: line.trim().slice(0, 160),
        });
      }
    }
  });

  return {
    passed: violations.length === 0,
    violations,
    legitimateReferences,
  };
}

function collectFiles(targetPath, out = []) {
  if (!fs.existsSync(targetPath)) return out;
  const stat = fs.statSync(targetPath);
  if (stat.isFile()) {
    if (/\.(?:ts|tsx|js|mjs|cjs|md|yml|yaml|json)$/i.test(targetPath)) {
      out.push(targetPath);
    }
    return out;
  }
  if (stat.isDirectory()) {
    const base = path.basename(targetPath);
    if (['node_modules', 'dist', 'dist-desktop', '.git', 'coverage'].includes(base)) {
      return out;
    }
    for (const entry of fs.readdirSync(targetPath)) {
      collectFiles(path.join(targetPath, entry), out);
    }
  }
  return out;
}

export function runSelfTestSuite() {
  // Scenario 1: Legitimate reference to user-authorized optional integration (including real PrivacyAndTermsModal text)
  const scenario1 = evaluatePositioningText(
    'O motor principal executa 100% offline e localmente. Fragmentos de código só são transmitidos para APIs externas (@google/genai Gemini, SonarQube Cloud/Server ou GitHub) quando você mesmo configura sua chave/token e autoriza a ação.',
    'src/components/PrivacyAndTermsModal.tsx'
  );
  assert.equal(scenario1.passed, true, 'Scenario 1 must pass legitimate user-authorized integration disclosure');
  assert.equal(scenario1.legitimateReferences.length, 1);

  // Scenario 2: Legitimate technical API compatibility statement
  const scenario2 = evaluatePositioningText(
    'This optional connector provides technical API compatibility with SonarQube Cloud/Server Web API endpoints when configured by the user.',
    'docs/integrations.md'
  );
  assert.equal(scenario2.passed, true, 'Scenario 2 must pass legitimate technical compatibility statement');

  // Scenario 3: False claim of official partnership
  const scenario3 = evaluatePositioningText(
    'WinHood Benchmarking is officially partnered with SonarQube to deliver enterprise audits.',
    'README.md'
  );
  assert.equal(scenario3.passed, false, 'Scenario 3 must reject false official partnership claims');
  assert.equal(scenario3.violations[0].ruleId, 'FALSE_OFFICIAL_PARTNERSHIP');

  // Scenario 4: Unverified third-party certification claim
  const scenario4 = evaluatePositioningText(
    'WinHood é certificado oficialmente pela OWASP e homologado oficialmente pela SonarSource.',
    'README.md'
  );
  assert.equal(scenario4.passed, false, 'Scenario 4 must reject unverified third-party certification');
  assert.equal(scenario4.violations[0].ruleId, 'UNVERIFIED_THIRD_PARTY_CERTIFICATION');

  // Scenario 5: Misidentification of WinHood as a third-party product
  const scenario5 = evaluatePositioningText(
    'WinHood is an official SonarQube product for desktop benchmarking.',
    'src/App.tsx'
  );
  assert.equal(scenario5.passed, false, 'Scenario 5 must reject misidentification as third-party product');
  assert.equal(scenario5.violations[0].ruleId, 'MISIDENTIFICATION_AS_THIRD_PARTY_PRODUCT');

  return {
    passed: true,
    scenariosTested: 5,
  };
}

export function scanRepositoryPositioning(rootDir = process.cwd()) {
  const targets = [
    'README.md',
    'docs',
    'src',
    'server.ts',
    'cli',
    'packages',
    'integrations',
    'examples',
    'templates',
  ];
  const files = [];
  for (const rel of targets) {
    collectFiles(path.resolve(rootDir, rel), files);
  }

  const allViolations = [];
  const allLegitimateReferences = [];

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');
    const relPath = path.relative(rootDir, file).replace(/\\/g, '/');
    const res = evaluatePositioningText(content, relPath);
    allViolations.push(...res.violations);
    allLegitimateReferences.push(...res.legitimateReferences);
  }

  return {
    passed: allViolations.length === 0,
    filesScanned: files.length,
    violations: allViolations,
    legitimateReferences: allLegitimateReferences,
  };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);
if (isMain) {
  const selfTest = runSelfTestSuite();
  const repoScan = scanRepositoryPositioning(process.cwd());
  if (!repoScan.passed) {
    console.error('[WinHood Positioning Verifier] FAILED — Prohibited deceptive claims detected:');
    for (const v of repoScan.violations) {
      console.error(`  - ${v.filePath}:${v.line} [${v.ruleId}] ${v.description}: "${v.excerpt}"`);
    }
    process.exit(1);
  }
  console.log(
    `[WinHood Positioning Verifier] PASSED — Scanned ${repoScan.filesScanned} files, ${selfTest.scenariosTested}/5 self-test scenarios verified, 0 deceptive affiliation/certification claims, ${repoScan.legitimateReferences.length} contextualized technical/privacy disclosures allowed.`
  );
}
