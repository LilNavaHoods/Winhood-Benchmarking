import { RULE_ENGINE_VERSION } from '../analyzers/RuleRegistry';

export const WINHOOD_API_SEMVER = '4.3.0';

export function buildOpenApiSpec(serverOrigin = 'http://localhost:3000'): Record<string, unknown> {
  return {
    openapi: '3.0.3',
    info: {
      title: 'WinHood Independent Audit & Benchmarking API',
      version: WINHOOD_API_SEMVER,
      description:
        'Open-standards REST API for independent static/taint/secrets/IaC analysis, signed SBOM (CycloneDX 1.5 / SPDX 2.3), SARIF 2.1.0 interoperability, versioned Quality Gates, cryptographic evidence chains, and portfolio governance.',
      license: {
        name: 'MIT',
      },
    },
    servers: [{ url: serverOrigin, description: 'Active WinHood Runtime' }],
    paths: {
      '/api/health': {
        get: {
          summary: 'Health check and runtime environment telemetry',
          responses: { '200': { description: 'Backend operational status' } },
        },
      },
      '/api/openapi.json': {
        get: {
          summary: 'OpenAPI 3.0.3 machine-readable API contract',
          responses: { '200': { description: 'OpenAPI JSON document' } },
        },
      },
      '/api/totp/status': {
        get: {
          summary: 'Inspect optional TOTP 2FA status (enabled/unlocked); unrestricted local access when disabled',
          responses: { '200': { description: 'Optional TOTP status payload' } },
        },
      },
      '/api/totp/setup': {
        post: {
          summary: 'Generate RFC-6238 TOTP secret, otpauth URI, QR Code data URL, and 8 single-use recovery codes',
          responses: { '200': { description: 'Pending TOTP setup bundle' } },
        },
      },
      '/api/totp/confirm': {
        post: {
          summary: 'Confirm first 6-digit TOTP code to enable optional 2FA protection',
          responses: { '200': { description: 'Optional TOTP enabled and current session unlocked' } },
        },
      },
      '/api/totp/verify': {
        post: {
          summary: 'Unlock local workspace using a 6-digit TOTP code or single-use recovery code',
          responses: { '200': { description: 'Session unlocked' }, '401': { description: 'Invalid or replayed code' } },
        },
      },
      '/api/totp/disable': {
        post: {
          summary: 'Disable optional TOTP 2FA protection after verifying a valid TOTP or recovery code',
          responses: { '200': { description: 'Optional TOTP disabled; unrestricted local access restored' } },
        },
      },
      '/api/totp/lock': {
        post: {
          summary: 'Manually lock the current local session when optional TOTP 2FA is active',
          responses: { '200': { description: 'Session locked' } },
        },
      },
      '/api/rules/catalog': {
        get: {
          summary: 'Public versioned rule catalog (CWE, OWASP Top 10, CVSS, examples, packs SHA-256)',
          responses: { '200': { description: 'Versioned rule catalog snapshot' } },
        },
      },
      '/api/secrets/catalog': {
        get: {
          summary: 'Public versioned secret detection patterns and false-positive exclusions',
          responses: { '200': { description: 'Versioned secrets catalog' } },
        },
      },
      '/api/analyze/sarif': {
        post: {
          summary: 'Run native analysis pipeline on submitted source files or import external SARIF 2.1.0',
          responses: { '200': { description: 'SARIF 2.1.0 output and deterministic digest' } },
        },
      },
      '/api/runs': {
        get: {
          summary: 'List all benchmark and audit runs',
          responses: { '200': { description: 'Array of benchmark runs' } },
        },
        post: {
          summary: 'Execute a full deterministic benchmark and security audit run',
          responses: { '201': { description: 'Completed run with signed manifest and SBOMs' } },
        },
      },
      '/api/runs/{runId}/sbom': {
        get: {
          summary: 'Retrieve signed CycloneDX 1.5 / SPDX 2.3 SBOM and verification proof',
          parameters: [{ name: 'runId', in: 'path', required: true, schema: { type: 'string' } }],
          responses: { '200': { description: 'SBOM bundle with cryptographic signature' } },
        },
      },
      '/api/reports/{runId}/export': {
        get: {
          summary: 'Export run report in json, sarif, html, pdf, csv, or md format',
          parameters: [
            { name: 'runId', in: 'path', required: true, schema: { type: 'string' } },
            {
              name: 'format',
              in: 'query',
              required: false,
              schema: { type: 'string', enum: ['json', 'sarif', 'html', 'pdf', 'csv', 'md'] },
            },
          ],
          responses: { '200': { description: 'Exported audit artifact' } },
        },
      },
      '/api/evidence/{runId}/verify': {
        get: {
          summary: 'Cryptographically verify SHA-256 evidence chain, HMAC-SHA256, Ed25519, and extended governance metadata',
          parameters: [{ name: 'runId', in: 'path', required: true, schema: { type: 'string' } }],
          responses: { '200': { description: 'Verification result' } },
        },
      },
      '/api/quality-gates': {
        get: {
          summary: 'List versioned Quality Gate definitions',
          responses: { '200': { description: 'Array of versioned Quality Gates' } },
        },
        post: {
          summary: 'Create or register a custom versioned Quality Gate',
          responses: { '201': { description: 'Registered gate with SHA-256 hash' } },
        },
      },
      '/api/quality-gates/evaluate': {
        post: {
          summary: 'Evaluate a run or findings payload against a versioned Quality Gate and return CLI exit code',
          responses: { '200': { description: 'Gate evaluation decision (APPROVED/BLOCKED/INCONCLUSIVE/REJECTED)' } },
        },
      },
      '/api/webhooks/sign-test': {
        post: {
          summary: 'Generate or dispatch an SSRF-guarded HMAC-SHA256 signed Quality Gate webhook',
          responses: { '200': { description: 'Signed webhook payload and optional delivery telemetry' } },
        },
      },
      '/api/compliance/{runId}/matrix': {
        get: {
          summary: 'Traceability mapping of findings to OWASP Top 10, CWE Top 25, PCI DSS v4.0, and ISO/IEC 27001:2022 (non-certification)',
          parameters: [{ name: 'runId', in: 'path', required: true, schema: { type: 'string' } }],
          responses: { '200': { description: 'Compliance traceability matrix' } },
        },
      },
      '/api/portfolio/summary': {
        get: {
          summary: 'Portfolio governance summary: release progression, finding trends, technical debt, covered vs. uncovered scope, and evidence confidence',
          responses: { '200': { description: 'Portfolio summary metrics' } },
        },
      },
      '/api/integrations/pr-decoration': {
        post: {
          summary: 'Generate PR/MR decoration markdown comment with gate decision, findings delta, and evidence digest',
          responses: { '200': { description: 'Structured PR/MR comment payload' } },
        },
      },
    },
    'x-winhood-engine-version': RULE_ENGINE_VERSION,
  };
}
