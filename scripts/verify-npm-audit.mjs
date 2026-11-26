#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';

/**
 * WinHood NPM Vulnerability Audit & Exception Governance Gate
 *
 * Enforces strict exact-match governance:
 * - Zero critical/high/moderate vulnerabilities in runtime production dependencies.
 * - Any governed build/dev exception in `security/npm-audit-exceptions.json` MUST match:
 *   1. Exact package name
 *   2. Exact advisoryId (every individual advisory in `via` must be explicitly covered)
 *   3. Exact severity (an exception for moderate/high never approves critical)
 *   4. Version / affectedRange compatibility
 *   5. Dependency path consistency (when present in audit nodes)
 *   6. Valid approval & non-expired expiration dates (approvedAt <= now < expiresAt)
 *   7. Zero duplicate or ambiguous exceptions in the registry
 * - Never reports governed exceptions as ZERO_VULNERABILITIES.
 * - Fails closed on any unapproved, mismatched, ambiguous, or expired advisory.
 */

export const DEFAULT_EXCEPTION_REGISTRY_PATH = path.resolve(
  process.cwd(),
  'security/npm-audit-exceptions.json'
);

const VALID_SEVERITIES = new Set(['low', 'moderate', 'high', 'critical']);
const BLOCKING_SEVERITIES = new Set(['moderate', 'high', 'critical']);
const GHSA_RE = /\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b/i;
const CVE_RE = /\bCVE-\d{4}-\d{4,}\b/i;

function resolveSafeNpmBinary() {
  const candidates =
    process.platform === 'win32'
      ? [
          path.join(path.dirname(process.execPath), 'npm.cmd'),
          'C:\\Program Files\\nodejs\\npm.cmd',
        ]
      : [
          path.join(path.dirname(process.execPath), 'npm'),
          '/usr/local/bin/npm',
          '/usr/bin/npm',
        ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

function getSafeAuditPathEnv() {
  const nodeBinDir = path.dirname(process.execPath);
  if (process.platform === 'win32') {
    const sysRoot = process.env.SystemRoot || 'C:\\Windows';
    return `${nodeBinDir};${sysRoot}\\System32;${sysRoot}`;
  }
  return `${nodeBinDir}:/usr/local/bin:/usr/bin:/bin`;
}

export function normalizeAdvisoryId(rawId) {
  const text = String(rawId || '').trim();
  if (!text) return '';
  const ghsa = text.match(GHSA_RE);
  if (ghsa) return ghsa[0].toUpperCase();
  const cve = text.match(CVE_RE);
  if (cve) return cve[0].toUpperCase();
  return text.toUpperCase();
}

function extractAdvisoryIdFromViaObject(viaObj) {
  if (!viaObj || typeof viaObj !== 'object') return null;
  if (typeof viaObj.url === 'string') {
    const ghsa = viaObj.url.match(GHSA_RE);
    if (ghsa) return ghsa[0].toUpperCase();
    const cve = viaObj.url.match(CVE_RE);
    if (cve) return cve[0].toUpperCase();
  }
  if (viaObj.advisoryId) return normalizeAdvisoryId(viaObj.advisoryId);
  if (viaObj.source !== undefined && viaObj.source !== null) {
    return `NPM-ADVISORY-${String(viaObj.source).trim()}`;
  }
  if (typeof viaObj.title === 'string' && viaObj.title.trim()) {
    return `TITLE:${viaObj.title.trim().toUpperCase()}`;
  }
  return null;
}

function parseSemverLoose(ver) {
  const cleaned = String(ver || '').trim().replace(/^[v=]+/i, '');
  const m = cleaned.match(/^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/);
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease: m[4] || null,
  };
}

function compareSemverLoose(a, b) {
  const pa = parseSemverLoose(a);
  const pb = parseSemverLoose(b);
  if (!pa || !pb) return null;
  if (pa.major !== pb.major) return pa.major < pb.major ? -1 : 1;
  if (pa.minor !== pb.minor) return pa.minor < pb.minor ? -1 : 1;
  if (pa.patch !== pb.patch) return pa.patch < pb.patch ? -1 : 1;
  if (pa.prerelease && !pb.prerelease) return -1;
  if (!pa.prerelease && pb.prerelease) return 1;
  if (pa.prerelease && pb.prerelease) {
    return pa.prerelease.localeCompare(pb.prerelease);
  }
  return 0;
}

function versionSatisfiesSingleComparator(version, comparator) {
  const comp = comparator.trim();
  if (!comp || comp === '*') return true;
  const m = comp.match(/^(<=|>=|<|>|=)?\s*([v0-9A-Za-z.+-]+)$/);
  if (!m) return false;
  const op = m[1] || '=';
  const target = m[2];
  const cmp = compareSemverLoose(version, target);
  if (cmp === null) return version.trim() === target.trim();
  switch (op) {
    case '=':
      return cmp === 0;
    case '<':
      return cmp < 0;
    case '<=':
      return cmp <= 0;
    case '>':
      return cmp > 0;
    case '>=':
      return cmp >= 0;
    default:
      return false;
  }
}

export function versionMatchesRange(version, rangeExpr) {
  const rawRange = String(rangeExpr || '').trim();
  if (!rawRange || rawRange === '*') return true;
  const rawVer = String(version || '').trim();
  if (!rawVer) return false;
  // Handle OR branches (||)
  const branches = rawRange.split('||').map((b) => b.trim()).filter(Boolean);
  return branches.some((branch) => {
    // Handle hyphen ranges "1.0.0 - 2.0.0"
    const hyphen = branch.match(/^([0-9A-Za-z.+-]+)\s+-\s+([0-9A-Za-z.+-]+)$/);
    if (hyphen) {
      return (
        versionSatisfiesSingleComparator(rawVer, `>=${hyphen[1]}`) &&
        versionSatisfiesSingleComparator(rawVer, `<=${hyphen[2]}`)
      );
    }
    const parts = branch.split(/\s+/).filter(Boolean);
    return parts.every((part) => versionSatisfiesSingleComparator(rawVer, part));
  });
}

function dependencyPathMatches(exceptionPath, vulnNodes, pkgName) {
  if (!Array.isArray(vulnNodes) || vulnNodes.length === 0) return true;
  const normalizedExPath = String(exceptionPath || '')
    .toLowerCase()
    .replace(/@[^>\s]+/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  const exSegments = normalizedExPath
    .split('>')
    .map((s) => s.trim())
    .filter(Boolean);

  return vulnNodes.every((nodePath) => {
    const cleanNode = String(nodePath || '').replace(/\\/g, '/').toLowerCase();
    const parts = cleanNode.split('node_modules/').filter(Boolean).map((p) => p.replace(/\/+$/, ''));
    if (parts.length === 0) return true;
    const leaf = parts[parts.length - 1];
    if (leaf !== pkgName.toLowerCase()) return false;
    if (exSegments.length === 0) return false;
    // The exception path must end with the vulnerable package and contain all path segments when nested
    if (exSegments[exSegments.length - 1] !== leaf) return false;
    if (parts.length === 1) return true;
    return parts.every((seg) => exSegments.includes(seg));
  });
}

export function validateExceptionEntry(entry, now = new Date()) {
  if (!entry || typeof entry !== 'object') {
    return { valid: false, reason: 'Exception entry must be an object' };
  }
  const requiredFields = [
    'advisoryId',
    'package',
    'version',
    'dependencyPath',
    'severity',
    'fixAvailable',
    'winhoodImpact',
    'justification',
    'compensatingControl',
    'owner',
    'approvedAt',
    'expiresAt',
    'removalCondition',
  ];
  for (const field of requiredFields) {
    if (entry[field] === undefined || entry[field] === null || String(entry[field]).trim() === '') {
      return { valid: false, reason: `Missing required governance field '${field}'` };
    }
  }
  const sev = String(entry.severity).toLowerCase().trim();
  if (!VALID_SEVERITIES.has(sev)) {
    return { valid: false, reason: `Invalid severity '${entry.severity}'` };
  }
  const approved = new Date(entry.approvedAt);
  if (Number.isNaN(approved.getTime())) {
    return { valid: false, reason: `Invalid approvedAt timestamp '${entry.approvedAt}'` };
  }
  const expires = new Date(entry.expiresAt);
  if (Number.isNaN(expires.getTime())) {
    return { valid: false, reason: `Invalid expiresAt timestamp '${entry.expiresAt}'` };
  }
  if (expires.getTime() <= approved.getTime()) {
    return {
      valid: false,
      reason: `Exception for '${entry.package}' (${entry.advisoryId}) has expiresAt <= approvedAt`,
    };
  }
  if (approved.getTime() > now.getTime()) {
    return {
      valid: false,
      reason: `Exception for '${entry.package}' (${entry.advisoryId}) has future approvedAt '${entry.approvedAt}'`,
    };
  }
  if (expires.getTime() <= now.getTime()) {
    return {
      valid: false,
      reason: `Exception for '${entry.package}' (${entry.advisoryId}) expired at ${entry.expiresAt}`,
    };
  }
  return { valid: true };
}

function collectIndividualAdvisories(pkgName, vulnInfo, allVulns, visited = new Set()) {
  const visitKey = `${pkgName}`;
  if (visited.has(visitKey)) return [];
  visited.add(visitKey);

  const viaList = Array.isArray(vulnInfo?.via) ? vulnInfo.via : [];
  const extracted = [];

  for (const viaItem of viaList) {
    if (viaItem && typeof viaItem === 'object') {
      const advisoryId = extractAdvisoryIdFromViaObject(viaItem);
      extracted.push({
        advisoryId: advisoryId || `UNKNOWN_ADVISORY:${pkgName}`,
        severity: String(viaItem.severity || vulnInfo.severity || 'unknown').toLowerCase(),
        range: String(viaItem.range || vulnInfo.range || '*'),
        sourcePackage: String(viaItem.name || pkgName),
        transitive: false,
      });
    } else if (typeof viaItem === 'string' && viaItem.trim()) {
      const upstream = allVulns[viaItem];
      if (upstream) {
        const upstreamAdvs = collectIndividualAdvisories(viaItem, upstream, allVulns, new Set(visited));
        if (upstreamAdvs.length > 0) {
          for (const adv of upstreamAdvs) {
            extracted.push({
              advisoryId: adv.advisoryId,
              severity: String(vulnInfo.severity || adv.severity || 'unknown').toLowerCase(),
              range: String(vulnInfo.range || adv.range || '*'),
              sourcePackage: adv.sourcePackage,
              transitive: true,
            });
          }
          continue;
        }
      }
      extracted.push({
        advisoryId: `TRANSITIVE:${viaItem.trim().toUpperCase()}`,
        severity: String(vulnInfo.severity || 'unknown').toLowerCase(),
        range: String(vulnInfo.range || '*'),
        sourcePackage: viaItem.trim(),
        transitive: true,
      });
    }
  }

  // Fallback when audit report omitted `via` array (synthetic minimal report)
  if (extracted.length === 0) {
    extracted.push({
      advisoryId: vulnInfo?.advisoryId
        ? normalizeAdvisoryId(vulnInfo.advisoryId)
        : `UNSPECIFIED_ADVISORY:${pkgName.toUpperCase()}`,
      severity: String(vulnInfo?.severity || 'unknown').toLowerCase(),
      range: String(vulnInfo?.range || '*'),
      sourcePackage: pkgName,
      transitive: false,
    });
  }

  // Deduplicate by advisoryId + severity
  const unique = new Map();
  for (const item of extracted) {
    const key = `${item.advisoryId}|${item.severity}`;
    if (!unique.has(key)) unique.set(key, item);
  }
  return Array.from(unique.values());
}

export function evaluateAuditReport(auditJson, exceptionsRegistry, now = new Date()) {
  const vulns = auditJson?.vulnerabilities || {};
  const approvedList = Array.isArray(exceptionsRegistry?.exceptions)
    ? exceptionsRegistry.exceptions
    : [];

  const unapprovedVulnerabilities = [];
  const expiredOrInvalidExceptions = [];
  const duplicateOrAmbiguousExceptions = [];
  const activeGovernedExceptions = [];
  const severityCounts = { critical: 0, high: 0, moderate: 0, low: 0, info: 0 };

  // 1. Validate every registry entry & reject duplicate/ambiguous exceptions
  const seenExceptionKeys = new Map();
  for (const ex of approvedList) {
    const check = validateExceptionEntry(ex, now);
    if (!check.valid) {
      expiredOrInvalidExceptions.push({
        package: ex?.package || 'unknown',
        advisoryId: ex?.advisoryId || 'unknown',
        reason: check.reason,
      });
    }
    const normKey = `${String(ex?.package || '').toLowerCase()}::${normalizeAdvisoryId(ex?.advisoryId)}`;
    if (seenExceptionKeys.has(normKey)) {
      duplicateOrAmbiguousExceptions.push({
        package: ex?.package || 'unknown',
        advisoryId: ex?.advisoryId || 'unknown',
        reason: `Duplicate or ambiguous exception registered for ${ex?.package} (${normalizeAdvisoryId(ex?.advisoryId)})`,
      });
    } else {
      seenExceptionKeys.set(normKey, ex);
    }
  }

  // 2. Evaluate every vulnerability and EVERY individual advisory inside `via`
  for (const [pkgName, vulnInfo] of Object.entries(vulns)) {
    const pkgSeverity = String(vulnInfo?.severity || 'unknown').toLowerCase();
    if (pkgSeverity in severityCounts) {
      severityCounts[pkgSeverity] += 1;
    }
    if (!BLOCKING_SEVERITIES.has(pkgSeverity)) continue;

    const advisories = collectIndividualAdvisories(pkgName, vulnInfo, vulns);
    const installedVersion =
      typeof vulnInfo?.version === 'string' && vulnInfo.version.trim()
        ? vulnInfo.version.trim()
        : null;

    for (const adv of advisories) {
      const effectiveSeverity = BLOCKING_SEVERITIES.has(adv.severity) ? adv.severity : pkgSeverity;
      if (!BLOCKING_SEVERITIES.has(effectiveSeverity)) continue;

      const normAdvId = normalizeAdvisoryId(adv.advisoryId);
      const candidates = approvedList.filter(
        (e) => String(e?.package || '').toLowerCase() === pkgName.toLowerCase()
      );

      if (candidates.length === 0) {
        unapprovedVulnerabilities.push({
          package: pkgName,
          advisoryId: normAdvId,
          severity: effectiveSeverity,
          range: adv.range,
          installedVersion,
          isDirect: Boolean(vulnInfo?.isDirect),
          reason: `No exception registered for package '${pkgName}' (${normAdvId})`,
        });
        continue;
      }

      // Exact advisoryId match required (never allow advisory A to approve advisory B on same package)
      const advMatches = candidates.filter((e) => {
        const exAdv = normalizeAdvisoryId(e.advisoryId);
        return exAdv === normAdvId;
      });

      if (advMatches.length === 0) {
        unapprovedVulnerabilities.push({
          package: pkgName,
          advisoryId: normAdvId,
          severity: effectiveSeverity,
          range: adv.range,
          installedVersion,
          isDirect: Boolean(vulnInfo?.isDirect),
          reason: `Exception exists for '${pkgName}' but does NOT cover advisory '${normAdvId}'`,
        });
        continue;
      }

      if (advMatches.length > 1) {
        unapprovedVulnerabilities.push({
          package: pkgName,
          advisoryId: normAdvId,
          severity: effectiveSeverity,
          range: adv.range,
          installedVersion,
          reason: `Ambiguous multiple exceptions matched '${pkgName}' (${normAdvId})`,
        });
        continue;
      }

      const matched = advMatches[0];
      const entryCheck = validateExceptionEntry(matched, now);
      if (!entryCheck.valid) {
        unapprovedVulnerabilities.push({
          package: pkgName,
          advisoryId: normAdvId,
          severity: effectiveSeverity,
          range: adv.range,
          installedVersion,
          reason: entryCheck.reason,
        });
        continue;
      }

      // Exact severity match required
      const exSeverity = String(matched.severity || '').toLowerCase().trim();
      if (exSeverity !== effectiveSeverity) {
        unapprovedVulnerabilities.push({
          package: pkgName,
          advisoryId: normAdvId,
          severity: effectiveSeverity,
          range: adv.range,
          installedVersion,
          reason: `Severity mismatch for '${pkgName}' (${normAdvId}): exception allows '${exSeverity}', audit reported '${effectiveSeverity}'`,
        });
        continue;
      }

      // Installed version / affectedRange check
      if (installedVersion && matched.version !== installedVersion) {
        unapprovedVulnerabilities.push({
          package: pkgName,
          advisoryId: normAdvId,
          severity: effectiveSeverity,
          range: adv.range,
          installedVersion,
          reason: `Installed version mismatch for '${pkgName}': exception covers '${matched.version}', audit reported '${installedVersion}'`,
        });
        continue;
      }

      if (matched.affectedRange && adv.range && adv.range !== '*' && matched.affectedRange !== adv.range) {
        unapprovedVulnerabilities.push({
          package: pkgName,
          advisoryId: normAdvId,
          severity: effectiveSeverity,
          range: adv.range,
          installedVersion,
          reason: `Affected range mismatch for '${pkgName}': exception covers '${matched.affectedRange}', audit reported '${adv.range}'`,
        });
        continue;
      }

      if (!versionMatchesRange(matched.version, adv.range)) {
        unapprovedVulnerabilities.push({
          package: pkgName,
          advisoryId: normAdvId,
          severity: effectiveSeverity,
          range: adv.range,
          installedVersion,
          reason: `Exception version '${matched.version}' is outside audit affected range '${adv.range}'`,
        });
        continue;
      }

      // Dependency path consistency check
      if (!dependencyPathMatches(matched.dependencyPath, vulnInfo?.nodes, pkgName)) {
        unapprovedVulnerabilities.push({
          package: pkgName,
          advisoryId: normAdvId,
          severity: effectiveSeverity,
          range: adv.range,
          installedVersion,
          reason: `Dependency path mismatch for '${pkgName}': exception path '${matched.dependencyPath}' does not match audit nodes ${JSON.stringify(vulnInfo?.nodes)}`,
        });
        continue;
      }

      activeGovernedExceptions.push({
        package: pkgName,
        version: matched.version,
        severity: effectiveSeverity,
        advisoryId: normAdvId,
        dependencyPath: matched.dependencyPath,
        expiresAt: matched.expiresAt,
        removalCondition: matched.removalCondition,
      });
    }
  }

  const passed =
    unapprovedVulnerabilities.length === 0 &&
    expiredOrInvalidExceptions.length === 0 &&
    duplicateOrAmbiguousExceptions.length === 0;

  const totalBlockingAdvisories =
    severityCounts.critical + severityCounts.high + severityCounts.moderate;

  const honestStatus =
    Object.keys(vulns).length === 0
      ? 'ZERO_VULNERABILITIES'
      : !passed
        ? 'UNAPPROVED_VULNERABILITIES_BLOCKED'
        : activeGovernedExceptions.length > 0
          ? 'GOVERNED_BUILD_TIME_EXCEPTIONS_ACTIVE'
          : totalBlockingAdvisories === 0
            ? 'LOW_SEVERITY_ONLY_NO_BLOCKING_VULNERABILITIES'
            : 'UNAPPROVED_VULNERABILITIES_BLOCKED';

  return {
    passed,
    totalAdvisoriesCount: Object.keys(vulns).length,
    severityCounts,
    unapprovedCount: unapprovedVulnerabilities.length,
    activeGovernedExceptionsCount: activeGovernedExceptions.length,
    duplicateOrAmbiguousCount: duplicateOrAmbiguousExceptions.length,
    unapprovedVulnerabilities,
    expiredOrInvalidExceptions,
    duplicateOrAmbiguousExceptions,
    activeGovernedExceptions,
    honestStatus,
  };
}

export function runSelfTest() {
  const now = new Date('2026-11-17T12:00:00Z');

  const validRegistry = {
    exceptions: [
      {
        advisoryId: 'GHSA-fc5q-39xc-vjpf',
        package: 'picomatch',
        version: '4.0.7',
        affectedRange: '<=4.0.7',
        dependencyPath: 'vite > picomatch',
        severity: 'high',
        fixAvailable: 'No upstream picomatch > 4.0.7 published on npm registry yet',
        winhoodImpact:
          'Build-time dev bundler globbing only; never exposed to untrusted user input or runtime analysis',
        justification: 'Upstream picomatch latest release is 4.0.7',
        compensatingControl:
          'WinHood runtime uses internal bounded regex parser and disables external shell/glob execution on untrusted inputs',
        owner: 'WinHood AppSec & DevSecOps Team',
        approvedAt: '2026-11-17T00:00:00Z',
        expiresAt: '2027-02-17T00:00:00Z',
        removalCondition: 'Remove immediately when picomatch >= 4.0.8 is published to npm',
      },
    ],
  };

  // 1. Exact matching governed exception passes and NEVER claims ZERO_VULNERABILITIES
  const matchingAudit = {
    vulnerabilities: {
      picomatch: {
        name: 'picomatch',
        severity: 'high',
        version: '4.0.7',
        range: '<=4.0.7',
        nodes: ['node_modules/vite/node_modules/picomatch'],
        via: [
          {
            source: 1099001,
            name: 'picomatch',
            severity: 'high',
            url: 'https://github.com/advisories/GHSA-fc5q-39xc-vjpf',
            range: '<=4.0.7',
          },
        ],
      },
      'minor-info-pkg': { name: 'minor-info-pkg', severity: 'low', range: '<1.0.0' },
    },
  };
  const resPass = evaluateAuditReport(matchingAudit, validRegistry, now);
  assert.equal(resPass.passed, true);
  assert.equal(resPass.severityCounts.high, 1);
  assert.equal(resPass.severityCounts.low, 1);
  assert.equal(resPass.honestStatus, 'GOVERNED_BUILD_TIME_EXCEPTIONS_ACTIVE');
  assert.notEqual(resPass.honestStatus, 'ZERO_VULNERABILITIES');

  // 2. NEGATIVE TEST: Different advisory on the SAME package MUST fail
  const diffAdvisoryAudit = {
    vulnerabilities: {
      picomatch: {
        name: 'picomatch',
        severity: 'high',
        version: '4.0.7',
        range: '<=4.0.7',
        via: [
          {
            source: 2000001,
            name: 'picomatch',
            severity: 'high',
            url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
            range: '<=4.0.7',
          },
        ],
      },
    },
  };
  const resDiffAdv = evaluateAuditReport(diffAdvisoryAudit, validRegistry, now);
  assert.equal(resDiffAdv.passed, false, 'Exception for advisory A must NOT approve advisory B on same package');

  // 3. NEGATIVE TEST: Severity escalation (critical vs high) MUST fail
  const severityMismatchAudit = {
    vulnerabilities: {
      picomatch: {
        name: 'picomatch',
        severity: 'critical',
        version: '4.0.7',
        range: '<=4.0.7',
        via: [
          {
            source: 1099001,
            name: 'picomatch',
            severity: 'critical',
            url: 'https://github.com/advisories/GHSA-fc5q-39xc-vjpf',
            range: '<=4.0.7',
          },
        ],
      },
    },
  };
  const resSevMismatch = evaluateAuditReport(severityMismatchAudit, validRegistry, now);
  assert.equal(resSevMismatch.passed, false, 'High exception must NOT approve critical severity');

  // 4. NEGATIVE TEST: Unauthorized version MUST fail
  const wrongVersionAudit = {
    vulnerabilities: {
      picomatch: {
        name: 'picomatch',
        severity: 'high',
        version: '4.0.6',
        range: '<=4.0.7',
        via: [
          {
            source: 1099001,
            name: 'picomatch',
            severity: 'high',
            url: 'https://github.com/advisories/GHSA-fc5q-39xc-vjpf',
            range: '<=4.0.7',
          },
        ],
      },
    },
  };
  const resWrongVer = evaluateAuditReport(wrongVersionAudit, validRegistry, now);
  assert.equal(resWrongVer.passed, false, 'Exception for 4.0.7 must NOT approve 4.0.6');

  // 5. NEGATIVE TEST: Expired exception MUST fail
  const resExpired = evaluateAuditReport(
    matchingAudit,
    validRegistry,
    new Date('2027-03-01T00:00:00Z')
  );
  assert.equal(resExpired.passed, false, 'Expired exception must fail closed');

  // 6. NEGATIVE TEST: Duplicate/ambiguous exception MUST fail
  const dupRegistry = {
    exceptions: [validRegistry.exceptions[0], { ...validRegistry.exceptions[0] }],
  };
  const resDup = evaluateAuditReport(matchingAudit, dupRegistry, now);
  assert.equal(resDup.passed, false, 'Duplicate/ambiguous exception must fail closed');
  assert.equal(resDup.duplicateOrAmbiguousCount, 1);

  // 7. NEGATIVE TEST: Unapproved vulnerability MUST fail
  const resUnapproved = evaluateAuditReport(
    { vulnerabilities: { lodash: { name: 'lodash', severity: 'high', range: '<4.17.21' } } },
    validRegistry,
    now
  );
  assert.equal(resUnapproved.passed, false);

  // 8. Clean zero-vulnerability audit reports ZERO_VULNERABILITIES
  const resClean = evaluateAuditReport({ vulnerabilities: {} }, validRegistry, now);
  assert.equal(resClean.passed, true);
  assert.equal(resClean.honestStatus, 'ZERO_VULNERABILITIES');

  return true;
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);

if (isMain) {
  runSelfTest();
  const npmBin = resolveSafeNpmBinary();
  let rawAudit;
  try {
    rawAudit = execFileSync(npmBin, ['audit', '--json'], {
      encoding: 'utf8',
      shell: process.platform === 'win32',
      stdio: ['ignore', 'pipe', 'ignore'],
      env: { ...process.env, PATH: getSafeAuditPathEnv() },
    });
  } catch (err) {
    rawAudit = err.stdout ? String(err.stdout) : '{}';
  }
  const auditJson = JSON.parse(rawAudit || '{}');
  const registry = fs.existsSync(DEFAULT_EXCEPTION_REGISTRY_PATH)
    ? JSON.parse(fs.readFileSync(DEFAULT_EXCEPTION_REGISTRY_PATH, 'utf8'))
    : { exceptions: [] };

  const result = evaluateAuditReport(auditJson, registry, new Date());
  if (!result.passed) {
    console.error('[WinHood NPM Audit Governance] FAILED:', JSON.stringify(result, null, 2));
    process.exit(1);
  }
  console.log(
    `[WinHood NPM Audit Governance] PASSED — Status: ${result.honestStatus} (Critical: ${result.severityCounts.critical}, High: ${result.severityCounts.high}, Moderate: ${result.severityCounts.moderate}, Low: ${result.severityCounts.low} | Unapproved: 0, Governed Exceptions: ${result.activeGovernedExceptionsCount}/${result.totalAdvisoriesCount})`
  );
}
