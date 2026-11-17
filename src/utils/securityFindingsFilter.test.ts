import test from 'node:test';
import assert from 'node:assert/strict';
import type { NormalizedFinding } from '../types/benchmark';
import {
  computeSecurityFindingsFilterMetrics,
  DEFAULT_SECURITY_SUITE_FILTERS,
  filterSecuritySuiteFindings,
  normalizeFindingSeverityBucket,
  resolveFindingRemediationInfo,
  type SecuritySuiteFilterState,
} from './securityFindingsFilter';

function makeSampleFinding(overrides: Partial<NormalizedFinding>): NormalizedFinding {
  return {
    id: overrides.id || 'fnd-1',
    runId: 'run-1',
    softwareId: overrides.softwareId || 'sw-a',
    softwareName: overrides.softwareName || 'VaultCore Internal',
    softwareVersion: overrides.softwareVersion || '2.5.0',
    toolId: overrides.toolId || 'opengrep-sast',
    toolName: overrides.toolName || 'Opengrep SAST Engine',
    toolVersion: '1.9.0',
    category: overrides.category || 'SAST',
    originalRuleId: overrides.originalRuleId || 'typescript.sql-injection',
    title: overrides.title || 'SQL Injection via raw string concatenation',
    description: overrides.description || 'Unsanitized query execution',
    severity: overrides.severity || 'CRITICAL',
    confidence: 'HIGH',
    cleanCodeAttribute: 'RESPONSIBLE',
    mqrImpacts: [],
    isNewCode: true,
    filePath: overrides.filePath || 'src/db/query.ts',
    lineNumber: overrides.lineNumber || 42,
    component: 'db',
    snippet: 'db.query("SELECT * FROM users WHERE id=" + userId)',
    whyItIsAnIssue: 'Allows arbitrary SQL injection',
    evaluationImpactSummary: 'Severe security risk',
    remediationEffortMinutes: overrides.remediationEffortMinutes ?? 30,
    cwe: overrides.cwe || 'CWE-89',
    cve: overrides.cve,
    remediation: overrides.remediation || 'Use parameterized prepared statements.',
    evidenceSha256: overrides.evidenceSha256 || 'a1b2c3d4e5f60123456789abcdef0123456789abcdef0123456789abcdef0123',
    validationStatus: overrides.validationStatus || 'VALIDATED',
    lifecycleState: overrides.lifecycleState,
    collectedAt: '2026-11-17T00:00:00.000Z',
  };
}

const SAMPLE_FINDINGS: NormalizedFinding[] = [
  makeSampleFinding({
    id: 'f-crit-open',
    softwareId: 'sw-a',
    softwareName: 'VaultCore Internal',
    severity: 'CRITICAL',
    category: 'SAST',
    title: 'SQL Injection in Vault Repository',
    cwe: 'CWE-89',
    validationStatus: 'VALIDATED',
    lifecycleState: 'CONFIRMED',
    remediationEffortMinutes: 45,
  }),
  makeSampleFinding({
    id: 'f-high-remediating',
    softwareId: 'sw-a',
    softwareName: 'VaultCore Internal',
    severity: 'HIGH',
    category: 'SECRETS',
    title: 'Hardcoded Master Key Fallback',
    cwe: 'CWE-798',
    validationStatus: 'FIXED_PENDING_RETEST',
    lifecycleState: 'FIXED_PENDING_RETEST',
    remediationEffortMinutes: 25,
  }),
  makeSampleFinding({
    id: 'f-med-resolved',
    softwareId: 'sw-b',
    softwareName: 'KeeSafe Open',
    severity: 'MEDIUM',
    category: 'SCA',
    title: 'Outdated KDF Iteration Parameter',
    cwe: 'CWE-916',
    validationStatus: 'VERIFIED_RESOLVED',
    lifecycleState: 'VERIFIED_RESOLVED',
    remediationEffortMinutes: 20,
  }),
  makeSampleFinding({
    id: 'f-low-accepted',
    softwareId: 'sw-b',
    softwareName: 'KeeSafe Open',
    severity: 'LOW',
    category: 'CODE_QUALITY',
    title: 'Verbose Crypto Debug Banner',
    cwe: 'CWE-209',
    validationStatus: 'ACCEPTED',
    lifecycleState: 'ACCEPTED_RISK',
    remediationEffortMinutes: 10,
  }),
  makeSampleFinding({
    id: 'f-blocker-fp',
    softwareId: 'sw-b',
    softwareName: 'KeeSafe Open',
    severity: 'BLOCKER',
    category: 'DAST',
    title: 'Simulated Test Token in Fixture File',
    cwe: 'CWE-522',
    validationStatus: 'FALSE_POSITIVE_REVIEWED',
    lifecycleState: 'FALSE_POSITIVE',
    remediationEffortMinutes: 15,
  }),
];

test('normalizeFindingSeverityBucket maps all severity levels into Critical, High, Medium, Low', () => {
  assert.equal(normalizeFindingSeverityBucket('BLOCKER'), 'CRITICAL');
  assert.equal(normalizeFindingSeverityBucket('CRITICAL'), 'CRITICAL');
  assert.equal(normalizeFindingSeverityBucket('HIGH'), 'HIGH');
  assert.equal(normalizeFindingSeverityBucket('MEDIUM'), 'MEDIUM');
  assert.equal(normalizeFindingSeverityBucket('LOW'), 'LOW');
  assert.equal(normalizeFindingSeverityBucket('INFO'), 'LOW');
});

test('resolveFindingRemediationInfo resolves remediation buckets, 6-state validation, and exemption flags accurately', () => {
  const openInfo = resolveFindingRemediationInfo(SAMPLE_FINDINGS[0]!);
  assert.equal(openInfo.remediationBucket, 'OPEN_PENDING');
  assert.equal(openInfo.validationState6, 'CONFIRMADA');
  assert.equal(openInfo.lifecycleState, 'CONFIRMED');
  assert.equal(openInfo.isExempt, false);

  const inRemInfo = resolveFindingRemediationInfo(SAMPLE_FINDINGS[1]!);
  assert.equal(inRemInfo.remediationBucket, 'IN_REMEDIATION');
  assert.equal(inRemInfo.lifecycleState, 'FIXED_PENDING_RETEST');
  assert.equal(inRemInfo.isExempt, false);

  const resolvedInfo = resolveFindingRemediationInfo(SAMPLE_FINDINGS[2]!);
  assert.equal(resolvedInfo.remediationBucket, 'REMEDIATED');
  assert.equal(resolvedInfo.lifecycleState, 'VERIFIED_RESOLVED');
  assert.equal(resolvedInfo.isExempt, true);

  const acceptedInfo = resolveFindingRemediationInfo(SAMPLE_FINDINGS[3]!);
  assert.equal(acceptedInfo.remediationBucket, 'RISK_ACCEPTED');
  assert.equal(acceptedInfo.lifecycleState, 'ACCEPTED_RISK');
  assert.equal(acceptedInfo.isExempt, true);

  const fpInfo = resolveFindingRemediationInfo(SAMPLE_FINDINGS[4]!);
  assert.equal(fpInfo.remediationBucket, 'DISMISSED_FP');
  assert.equal(fpInfo.validationState6, 'FALSO_POSITIVO');
  assert.equal(fpInfo.isExempt, true);
});

test('filterSecuritySuiteFindings filters by single and multiple severities (Critical, High, Medium, Low)', () => {
  const critOnly = filterSecuritySuiteFindings(SAMPLE_FINDINGS, {
    ...DEFAULT_SECURITY_SUITE_FILTERS,
    severities: ['CRITICAL'],
  });
  assert.deepEqual(
    critOnly.map((f) => f.id),
    ['f-crit-open', 'f-blocker-fp']
  );

  const highAndMedium = filterSecuritySuiteFindings(SAMPLE_FINDINGS, {
    ...DEFAULT_SECURITY_SUITE_FILTERS,
    severities: ['HIGH', 'MEDIUM'],
  });
  assert.deepEqual(
    highAndMedium.map((f) => f.id),
    ['f-high-remediating', 'f-med-resolved']
  );

  const lowOnly = filterSecuritySuiteFindings(SAMPLE_FINDINGS, {
    ...DEFAULT_SECURITY_SUITE_FILTERS,
    severities: ['LOW'],
  });
  assert.deepEqual(
    lowOnly.map((f) => f.id),
    ['f-low-accepted']
  );
});

test('filterSecuritySuiteFindings filters by remediation status bucket and specific lifecycle state', () => {
  const openPending = filterSecuritySuiteFindings(SAMPLE_FINDINGS, {
    ...DEFAULT_SECURITY_SUITE_FILTERS,
    remediationStatus: 'OPEN_PENDING',
  });
  assert.deepEqual(
    openPending.map((f) => f.id),
    ['f-crit-open']
  );

  const inRemediation = filterSecuritySuiteFindings(SAMPLE_FINDINGS, {
    ...DEFAULT_SECURITY_SUITE_FILTERS,
    remediationStatus: 'IN_REMEDIATION',
  });
  assert.deepEqual(
    inRemediation.map((f) => f.id),
    ['f-high-remediating']
  );

  const remediated = filterSecuritySuiteFindings(SAMPLE_FINDINGS, {
    ...DEFAULT_SECURITY_SUITE_FILTERS,
    remediationStatus: 'REMEDIATED',
  });
  assert.deepEqual(
    remediated.map((f) => f.id),
    ['f-med-resolved']
  );

  const acceptedRisk = filterSecuritySuiteFindings(SAMPLE_FINDINGS, {
    ...DEFAULT_SECURITY_SUITE_FILTERS,
    remediationStatus: 'ACCEPTED_RISK',
  });
  assert.deepEqual(
    acceptedRisk.map((f) => f.id),
    ['f-low-accepted']
  );
});

test('filterSecuritySuiteFindings combines severity, remediation status, softwareId, category, and search query with local overrides', () => {
  const combinedFilters: SecuritySuiteFilterState = {
    severities: ['CRITICAL', 'HIGH'],
    remediationStatus: 'REMEDIATED',
    validationState: 'ALL',
    softwareId: 'sw-a',
    category: 'SAST',
    searchQuery: 'CWE-89',
  };

  // Before override, f-crit-open is OPEN_PENDING so it does not match REMEDIATED
  const beforeOverride = filterSecuritySuiteFindings(SAMPLE_FINDINGS, combinedFilters);
  assert.equal(beforeOverride.length, 0);

  // When overridden to VERIFIED_RESOLVED in local/global state, it matches immediately
  const afterOverride = filterSecuritySuiteFindings(SAMPLE_FINDINGS, combinedFilters, {
    lifecycleMap: { 'f-crit-open': 'VERIFIED_RESOLVED' },
  });
  assert.deepEqual(
    afterOverride.map((f) => f.id),
    ['f-crit-open']
  );

  const metrics = computeSecurityFindingsFilterMetrics(
    SAMPLE_FINDINGS,
    afterOverride,
    combinedFilters,
    { lifecycleMap: { 'f-crit-open': 'VERIFIED_RESOLVED' } }
  );
  assert.equal(metrics.totalFindings, 5);
  assert.equal(metrics.filteredCount, 1);
  assert.equal(metrics.bySeverity.CRITICAL, 2);
  assert.equal(metrics.bySeverity.HIGH, 1);
  assert.equal(metrics.bySeverity.MEDIUM, 1);
  assert.equal(metrics.bySeverity.LOW, 1);
  assert.equal(metrics.byRemediationBucket.REMEDIATED, 2);
  assert.equal(metrics.filteredEffortMinutes, 45);
  assert.equal(metrics.hasActiveFilters, true);
});
