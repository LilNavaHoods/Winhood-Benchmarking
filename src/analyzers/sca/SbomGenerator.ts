import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { KeyManagementService } from '../../security/KeyManagementService';
import type {
  SbomComponentRecord,
  SbomDocumentBundle,
  SbomLicenseProvenance,
  SbomSignatureRecord,
  Software,
} from '../../types/benchmark';

export const KNOWN_OSS_PACKAGE_LICENSES: Readonly<Record<string, string>> = {
  react: 'MIT',
  'react-dom': 'MIT',
  express: 'MIT',
  vite: 'MIT',
  '@vitejs/plugin-react': 'MIT',
  'lucide-react': 'ISC',
  tailwindcss: 'MIT',
  '@tailwindcss/vite': 'MIT',
  typescript: 'Apache-2.0',
  '@babel/parser': 'MIT',
  esbuild: 'MIT',
  dotenv: 'BSD-2-Clause',
  qrcode: 'MIT',
  motion: 'MIT',
  tsx: 'MIT',
  autoprefixer: 'MIT',
  '@google/genai': 'Apache-2.0',
  lodash: 'MIT',
  axios: 'MIT',
  jsonwebtoken: 'MIT',
  semver: 'ISC',
  minimist: 'MIT',
  ws: 'MIT',
  pg: 'MIT',
  redis: 'MIT',
  argon2: 'MIT',
  bcrypt: 'MIT',
  zod: 'MIT',
  helmet: 'MIT',
  cors: 'MIT',
  uuid: 'MIT',
  chalk: 'MIT',
  commander: 'MIT',
  vitest: 'MIT',
  playwright: 'Apache-2.0',
  electron: 'MIT',
  'electron-builder': 'MIT',
  postcss: 'MIT',
  eslint: 'MIT',
  prettier: 'MIT',
  django: 'BSD-3-Clause',
  flask: 'BSD-3-Clause',
  fastapi: 'MIT',
  requests: 'Apache-2.0',
  cryptography: 'Apache-2.0',
  pydantic: 'MIT',
  sqlalchemy: 'MIT',
  pytest: 'MIT',
};

const nodeModulesLicenseCache = new Map<string, string>();

export function resolvePackageSpdxLicenseWithProvenance(
  pkgName: string,
  explicitLicense?: string,
  rootManifestLicense?: string,
  options?: { strictProvenance?: boolean }
): { license: string; provenance: SbomLicenseProvenance } {
  const cleanExplicit = (explicitLicense || '').trim();
  if (cleanExplicit && cleanExplicit !== 'UNKNOWN' && cleanExplicit !== 'NOASSERTION') {
    return { license: cleanExplicit, provenance: 'LOCKFILE_DECLARED' };
  }
  const normalizedName = pkgName.trim();
  const lowerName = normalizedName.toLowerCase();

  // Check verifiable local node_modules/package.json first
  const cached = nodeModulesLicenseCache.get(normalizedName);
  if (cached) {
    return { license: cached, provenance: 'NODE_MODULES_DECLARED' };
  }
  try {
    const isSafeNpmPkgName =
      /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i.test(normalizedName) &&
      !normalizedName.includes('..') &&
      !normalizedName.includes('\\');
    if (isSafeNpmPkgName) {
      const nodeModulesRoot = path.resolve(process.cwd(), 'node_modules');
      const nmPkgPath = path.resolve(nodeModulesRoot, normalizedName, 'package.json');
      if (nmPkgPath.startsWith(`${nodeModulesRoot}${path.sep}`) && fs.existsSync(nmPkgPath)) {
        const parsed = JSON.parse(fs.readFileSync(nmPkgPath, 'utf8'));
        const lic =
          typeof parsed?.license === 'string'
            ? parsed.license.trim()
            : typeof parsed?.license?.type === 'string'
              ? parsed.license.type.trim()
              : '';
        if (lic) {
          nodeModulesLicenseCache.set(normalizedName, lic);
          return { license: lic, provenance: 'NODE_MODULES_DECLARED' };
        }
      }
    }
  } catch {
    // Ignore local node_modules read failures
  }

  // If strictProvenance is enabled, never infer license from package name or root project manifest
  if (options?.strictProvenance) {
    return { license: 'NOASSERTION', provenance: 'UNVERIFIED' };
  }

  if (KNOWN_OSS_PACKAGE_LICENSES[normalizedName]) {
    return {
      license: KNOWN_OSS_PACKAGE_LICENSES[normalizedName]!,
      provenance: 'KNOWN_ECOSYSTEM_REGISTRY',
    };
  }
  if (KNOWN_OSS_PACKAGE_LICENSES[lowerName]) {
    return {
      license: KNOWN_OSS_PACKAGE_LICENSES[lowerName]!,
      provenance: 'KNOWN_ECOSYSTEM_REGISTRY',
    };
  }
  if (normalizedName.startsWith('@types/')) {
    return { license: 'MIT', provenance: 'KNOWN_ECOSYSTEM_REGISTRY' };
  }

  const cleanRoot = (rootManifestLicense || '').trim();
  if (cleanRoot && cleanRoot !== 'UNKNOWN' && cleanRoot !== 'NOASSERTION') {
    return { license: cleanRoot, provenance: 'MANIFEST_DECLARED' };
  }
  return { license: 'NOASSERTION', provenance: 'UNVERIFIED' };
}

export function resolvePackageSpdxLicense(
  pkgName: string,
  explicitLicense?: string,
  rootManifestLicense?: string,
  options?: { strictProvenance?: boolean }
): string {
  return resolvePackageSpdxLicenseWithProvenance(
    pkgName,
    explicitLicense,
    rootManifestLicense,
    options
  ).license;
}

function deterministicUuidFromSeed(seed: string): string {
  const hex = crypto.createHash('sha256').update(seed, 'utf8').digest('hex').slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

const UUID_V4_URN_REGEX = /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PURL_REGEX = /^pkg:[a-z0-9.+-]+\/[^@]+@[^@]+$/i;
const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/i;
const ISO_TIMESTAMP_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

/**
 * SbomGenerator (Multi-Lockfile + Verifiable SPDX Provenance + CycloneDX 1.5/1.7 & SPDX 2.3/3.0.1 Schema Validation)
 * Generates CycloneDX 1.5 (default compatible), CycloneDX 1.7, SPDX 2.3 (default compatible), and SPDX 3.0.1 JSON-LD
 * documents directly from package manifests and lockfiles:
 * package.json, package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock,
 * requirements.txt, pyproject.toml, pom.xml, go.mod, Cargo.toml, Cargo.lock, *.csproj
 */
export class SbomGenerator {
  public static validateCycloneDxSchema(
    cdx: Record<string, any> | undefined,
    expectedSpecVersion: '1.5' | '1.7'
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    const prefix = `CycloneDX ${expectedSpecVersion}`;
    if (!cdx || typeof cdx !== 'object') {
      return { valid: false, errors: [`${prefix} JSON document missing.`] };
    }
    if (cdx.bomFormat !== 'CycloneDX') errors.push(`${prefix} bomFormat must be "CycloneDX".`);
    if (cdx.specVersion !== expectedSpecVersion) {
      errors.push(`${prefix} specVersion must be "${expectedSpecVersion}".`);
    }
    if (typeof cdx.serialNumber !== 'string' || !UUID_V4_URN_REGEX.test(cdx.serialNumber)) {
      errors.push(`${prefix} serialNumber must match urn:uuid:<UUID>.`);
    }
    if (typeof cdx.version !== 'number' || !Number.isInteger(cdx.version) || cdx.version < 1) {
      errors.push(`${prefix} version must be an integer >= 1.`);
    }
    if (typeof cdx.metadata?.timestamp !== 'string' || !ISO_TIMESTAMP_REGEX.test(cdx.metadata.timestamp)) {
      errors.push(`${prefix} metadata.timestamp must be a valid ISO-8601 UTC timestamp.`);
    }
    if (
      !cdx.metadata?.component ||
      typeof cdx.metadata.component.name !== 'string' ||
      !cdx.metadata.component.name.trim() ||
      typeof cdx.metadata.component.type !== 'string'
    ) {
      errors.push(`${prefix} metadata.component.name and type are required.`);
    }
    if (!Array.isArray(cdx.components)) {
      errors.push(`${prefix} components must be an array.`);
      return { valid: false, errors };
    }

    const knownRefs = new Set<string>();
    if (typeof cdx.metadata?.component?.['bom-ref'] === 'string') {
      knownRefs.add(cdx.metadata.component['bom-ref']);
    }

    for (let i = 0; i < cdx.components.length; i++) {
      const comp = cdx.components[i];
      if (!comp || typeof comp !== 'object') {
        errors.push(`${prefix} components[${i}] must be an object.`);
        continue;
      }
      if (typeof comp.name !== 'string' || !comp.name.trim()) {
        errors.push(`${prefix} components[${i}].name must be a non-empty string.`);
      }
      if (typeof comp.version !== 'string' || !comp.version.trim()) {
        errors.push(`${prefix} components[${i}].version must be a non-empty string.`);
      }
      const bomRef = comp['bom-ref'];
      if (typeof bomRef !== 'string' || !bomRef.trim()) {
        errors.push(`${prefix} components[${i}].bom-ref is required.`);
      } else if (knownRefs.has(bomRef)) {
        errors.push(`${prefix} duplicate bom-ref "${bomRef}".`);
      } else {
        knownRefs.add(bomRef);
      }
      if (comp.purl !== undefined && (typeof comp.purl !== 'string' || !PURL_REGEX.test(comp.purl))) {
        errors.push(`${prefix} components[${i}].purl invalid: "${comp.purl}".`);
      }
      if (Array.isArray(comp.hashes)) {
        for (const h of comp.hashes) {
          if (h?.alg === 'SHA-256' && !SHA256_HEX_REGEX.test(String(h?.content || ''))) {
            errors.push(`${prefix} components[${i}] has invalid SHA-256 digest.`);
          }
        }
      }
    }

    if (!Array.isArray(cdx.dependencies)) {
      errors.push(`${prefix} dependencies graph array is required.`);
    } else {
      for (const dep of cdx.dependencies) {
        if (!dep || typeof dep.ref !== 'string' || !knownRefs.has(dep.ref)) {
          errors.push(`${prefix} dependencies contains unknown ref "${dep?.ref}".`);
        }
        if (Array.isArray(dep?.dependsOn)) {
          for (const target of dep.dependsOn) {
            if (typeof target !== 'string' || !knownRefs.has(target)) {
              errors.push(`${prefix} dependency target "${target}" is dangling/missing from components.`);
            }
          }
        }
      }
    }

    return { valid: errors.length === 0, errors };
  }

  public static validateSpdx23Schema(spdx: Record<string, any> | undefined): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];
    if (!spdx || typeof spdx !== 'object') {
      return { valid: false, errors: ['SPDX 2.3 JSON document missing.'] };
    }
    if (spdx.spdxVersion !== 'SPDX-2.3') errors.push('SPDX 2.3 spdxVersion must be "SPDX-2.3".');
    if (spdx.dataLicense !== 'CC0-1.0') errors.push('SPDX 2.3 dataLicense must be "CC0-1.0".');
    if (spdx.SPDXID !== 'SPDXRef-DOCUMENT') errors.push('SPDX 2.3 SPDXID must be "SPDXRef-DOCUMENT".');
    if (typeof spdx.documentNamespace !== 'string' || !/^https?:\/\/.+/.test(spdx.documentNamespace)) {
      errors.push('SPDX 2.3 documentNamespace must be a valid URI.');
    }
    if (
      !spdx.creationInfo?.created ||
      !ISO_TIMESTAMP_REGEX.test(String(spdx.creationInfo.created)) ||
      !Array.isArray(spdx.creationInfo?.creators) ||
      spdx.creationInfo.creators.length === 0
    ) {
      errors.push('SPDX 2.3 creationInfo.created (ISO-8601) and non-empty creators are required.');
    }
    if (!Array.isArray(spdx.packages)) {
      errors.push('SPDX 2.3 packages must be an array.');
      return { valid: false, errors };
    }
    const pkgIds = new Set<string>();
    for (let i = 0; i < spdx.packages.length; i++) {
      const p = spdx.packages[i];
      if (!p || typeof p.SPDXID !== 'string' || !p.SPDXID.startsWith('SPDXRef-')) {
        errors.push(`SPDX 2.3 packages[${i}].SPDXID invalid.`);
      } else if (pkgIds.has(p.SPDXID)) {
        errors.push(`SPDX 2.3 duplicate SPDXID "${p.SPDXID}".`);
      } else {
        pkgIds.add(p.SPDXID);
      }
      if (typeof p.name !== 'string' || !p.name.trim()) {
        errors.push(`SPDX 2.3 packages[${i}].name must be non-empty.`);
      }
      if (typeof p.versionInfo !== 'string' || !p.versionInfo.trim()) {
        errors.push(`SPDX 2.3 packages[${i}].versionInfo must be non-empty.`);
      }
      if (typeof p.licenseDeclared !== 'string' || !p.licenseDeclared.trim()) {
        errors.push(`SPDX 2.3 packages[${i}].licenseDeclared must be a valid expression or NOASSERTION.`);
      }
      if (Array.isArray(p.checksums)) {
        for (const c of p.checksums) {
          if (c?.algorithm === 'SHA256' && !SHA256_HEX_REGEX.test(String(c?.checksumValue || ''))) {
            errors.push(`SPDX 2.3 packages[${i}] has invalid SHA256 checksumValue.`);
          }
        }
      }
    }
    return { valid: errors.length === 0, errors };
  }

  public static validateSpdx30JsonLdSchema(spdx30: Record<string, any> | undefined): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];
    if (!spdx30 || typeof spdx30 !== 'object') {
      return { valid: false, errors: ['SPDX 3.0 JSON-LD document missing.'] };
    }
    if (spdx30['@context'] !== 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld') {
      errors.push('SPDX 3.0 @context must reference official SPDX 3.0.1 JSON-LD context.');
    }
    if (!Array.isArray(spdx30['@graph']) || spdx30['@graph'].length === 0) {
      errors.push('SPDX 3.0 @graph must be a non-empty array.');
      return { valid: false, errors };
    }

    const graphNodes = new Map<string, any>();
    let hasDocument = false;
    let hasCreationInfo = false;
    for (const node of spdx30['@graph']) {
      if (!node || typeof node !== 'object') {
        errors.push('SPDX 3.0 @graph contains non-object element.');
        continue;
      }
      if (node.type === 'SpdxDocument') hasDocument = true;
      if (node.type === 'CreationInfo') hasCreationInfo = true;
      if (typeof node.spdxId === 'string') {
        graphNodes.set(node.spdxId, node);
      }
      if (node.type === 'software_Package') {
        if (typeof node.name !== 'string' || !node.name.trim()) {
          errors.push(`SPDX 3.0 software_Package "${node.spdxId}" missing name.`);
        }
        if (typeof node.software_packageVersion !== 'string' || !node.software_packageVersion.trim()) {
          errors.push(`SPDX 3.0 software_Package "${node.spdxId}" missing software_packageVersion.`);
        }
        if (
          typeof node.software_packageUrl !== 'string' ||
          !PURL_REGEX.test(node.software_packageUrl)
        ) {
          errors.push(`SPDX 3.0 software_Package "${node.spdxId}" has invalid PURL.`);
        }
      }
    }
    if (!hasDocument) errors.push('SPDX 3.0 @graph missing SpdxDocument element.');
    if (!hasCreationInfo) errors.push('SPDX 3.0 @graph missing CreationInfo element.');

    for (const node of spdx30['@graph']) {
      if (node?.type === 'Relationship') {
        if (!graphNodes.has(node.from)) {
          errors.push(`SPDX 3.0 Relationship missing "from" target "${node.from}".`);
        }
        if (Array.isArray(node.to)) {
          for (const target of node.to) {
            if (!graphNodes.has(target)) {
              errors.push(`SPDX 3.0 Relationship dangling "to" target "${target}".`);
            }
          }
        }
      }
    }

    return { valid: errors.length === 0, errors };
  }

  public static validateSbomBundle(bundle: SbomDocumentBundle): {
    cyclonedxValid: boolean;
    spdxValid: boolean;
    cyclonedx17Valid: boolean;
    spdx30Valid: boolean;
    schemaVersionValidated: string[];
    errors: string[];
  } {
    const cdx15 = SbomGenerator.validateCycloneDxSchema(
      bundle.cyclonedx15Json as Record<string, any> | undefined,
      '1.5'
    );
    const spdx23 = SbomGenerator.validateSpdx23Schema(
      bundle.spdx23Json as Record<string, any> | undefined
    );
    const cdx17 = bundle.cyclonedx17Json
      ? SbomGenerator.validateCycloneDxSchema(bundle.cyclonedx17Json as Record<string, any>, '1.7')
      : { valid: true, errors: [] };
    const spdx30 = bundle.spdx30Json
      ? SbomGenerator.validateSpdx30JsonLdSchema(bundle.spdx30Json as Record<string, any>)
      : { valid: true, errors: [] };

    const errors = [...cdx15.errors, ...spdx23.errors, ...cdx17.errors, ...spdx30.errors];
    const schemaVersionValidated: string[] = [];
    if (cdx15.valid) schemaVersionValidated.push('CycloneDX-1.5');
    if (cdx17.valid && bundle.cyclonedx17Json) schemaVersionValidated.push('CycloneDX-1.7');
    if (spdx23.valid) schemaVersionValidated.push('SPDX-2.3');
    if (spdx30.valid && bundle.spdx30Json) schemaVersionValidated.push('SPDX-3.0.1');

    return {
      cyclonedxValid: cdx15.valid,
      spdxValid: spdx23.valid,
      cyclonedx17Valid: cdx17.valid,
      spdx30Valid: spdx30.valid,
      schemaVersionValidated,
      errors,
    };
  }

  public static generateFromSoftware(
    software: Software,
    options?: {
      deterministicTimestamp?: string;
      signSbom?: boolean;
      strictLicenseProvenance?: boolean;
    }
  ): SbomDocumentBundle {
    const filesMap = software.sourceFilesContent || {};
    const { components, lockfilesDetected, transitiveCoverageComplete } =
      SbomGenerator.extractComponentsWithMetadata(filesMap, {
        strictLicenseProvenance: options?.strictLicenseProvenance,
      });
    const deterministicMode = Boolean(options?.deterministicTimestamp);
    const generatedAt = options?.deterministicTimestamp || new Date().toISOString();

    const directCount = components.filter(
      (c) => c.dependencyScope === 'DIRECT' || c.dependencyScope === 'DEV' || c.dependencyScope === 'OPTIONAL'
    ).length;
    const transitiveCount = components.filter((c) => c.dependencyScope === 'TRANSITIVE').length;
    const devCount = components.filter((c) => c.dependencyScope === 'DEV').length;
    const optionalCount = components.filter((c) => c.dependencyScope === 'OPTIONAL').length;
    const unresolvedDependenciesCount = components.filter(
      (c) =>
        c.versionResolutionState === 'UNRESOLVED' ||
        c.version === 'UNPINNED' ||
        c.version === 'MANAGED'
    ).length;
    const unknownLicenseCount = components.filter(
      (c) => !c.license || c.license === 'UNKNOWN' || c.license === 'NOASSERTION'
    ).length;
    const serialSeed = JSON.stringify({
      softwareId: software.id,
      version: software.version,
      components: components.map((c) => `${c.bomRef}:${c.sha256 || ''}`),
    });
    const docUuid = deterministicMode ? deterministicUuidFromSeed(serialSeed) : crypto.randomUUID();
    const appBomRef = `app:${software.id}@${software.version}`;
    const directRefs = components.filter((c) => c.dependencyScope !== 'TRANSITIVE').map((c) => c.bomRef);
    const transitiveRefs = components.filter((c) => c.dependencyScope === 'TRANSITIVE').map((c) => c.bomRef);

    const mappedComponents = components.map((c) => ({
      type: 'library',
      'bom-ref': c.bomRef,
      name: c.name,
      version: c.version,
      purl: c.purl,
      scope: c.dependencyScope === 'DIRECT' ? 'required' : 'optional',
      hashes: c.sha256 ? [{ alg: 'SHA-256', content: c.sha256 }] : [],
      licenses: c.license && c.license !== 'UNKNOWN' && c.license !== 'NOASSERTION'
        ? [{ license: { id: c.license } }]
        : [],
      properties: [
        { name: 'winhood:dependencyScope', value: c.dependencyScope },
        { name: 'winhood:licenseProvenance', value: c.licenseProvenance || 'UNVERIFIED' },
        { name: 'winhood:manifestFile', value: c.manifestFile },
        { name: 'winhood:ecosystem', value: c.ecosystem },
        ...(c.license === 'NOASSERTION' ? [{ name: 'winhood:spdxLicenseConclusion', value: 'NOASSERTION' }] : []),
      ],
    }));

    const cyclonedxDependencies = [
      {
        ref: appBomRef,
        dependsOn: directRefs.length > 0 ? directRefs : transitiveRefs,
      },
      ...components.map((c) => ({
        ref: c.bomRef,
        dependsOn: [] as string[],
      })),
    ];

    const cyclonedx15Json: Record<string, unknown> = {
      $schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json',
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${docUuid}`,
      version: 1,
      metadata: {
        timestamp: generatedAt,
        tools: [
          {
            vendor: 'WinHood',
            name: 'WinHood SBOM Generator',
            version: '4.4.0',
          },
        ],
        component: {
          type: 'application',
          name: software.name,
          version: software.version,
          'bom-ref': appBomRef,
        },
        properties: [
          {
            name: 'winhood:transitiveCoverageComplete',
            value: String(transitiveCoverageComplete),
          },
          {
            name: 'winhood:lockfilesDetected',
            value: lockfilesDetected.join(', ') || 'NONE',
          },
        ],
      },
      components: mappedComponents,
      dependencies: cyclonedxDependencies,
    };

    const cyclonedx17Json: Record<string, unknown> = {
      $schema: 'http://cyclonedx.org/schema/bom-1.7.schema.json',
      bomFormat: 'CycloneDX',
      specVersion: '1.7',
      serialNumber: `urn:uuid:${docUuid}`,
      version: 1,
      metadata: {
        timestamp: generatedAt,
        tools: {
          components: [
            {
              type: 'application',
              publisher: 'WinHood Engineering',
              name: 'WinHood SBOM Generator',
              version: '4.4.0',
            },
          ],
        },
        component: {
          type: 'application',
          name: software.name,
          version: software.version,
          'bom-ref': appBomRef,
        },
        properties: [
          {
            name: 'winhood:transitiveCoverageComplete',
            value: String(transitiveCoverageComplete),
          },
          {
            name: 'winhood:lockfilesDetected',
            value: lockfilesDetected.join(', ') || 'NONE',
          },
        ],
      },
      components: mappedComponents,
      dependencies: cyclonedxDependencies,
    };

    const spdx23Json: Record<string, unknown> = {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      name: `${software.name}-${software.version}-sbom`,
      documentNamespace: `https://winhood.local/spdx/${software.id}/${docUuid}`,
      creationInfo: {
        created: generatedAt,
        creators: ['Tool: WinHood SBOM Generator-4.4.0'],
      },
      documentDescribes: components.map((_, idx) => `SPDXRef-Package-${idx + 1}`),
      packages: components.map((c, idx) => ({
        SPDXID: `SPDXRef-Package-${idx + 1}`,
        name: c.name,
        versionInfo: c.version,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        checksums: c.sha256 ? [{ algorithm: 'SHA256', checksumValue: c.sha256 }] : [],
        licenseDeclared: c.license && c.license !== 'UNKNOWN' ? c.license : 'NOASSERTION',
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: c.purl,
          },
        ],
        comment: `dependencyScope=${c.dependencyScope}; licenseProvenance=${c.licenseProvenance || 'UNVERIFIED'}; manifest=${c.manifestFile}`,
      })),
    };

    const spdx30BaseUri = `https://winhood.local/spdx3/${software.id}/${docUuid}`;
    const spdx30CreationInfoId = `${spdx30BaseUri}/CreationInfo`;
    const spdx30DocId = `${spdx30BaseUri}/SpdxDocument`;
    const spdx30PkgIds = components.map((_, idx) => `${spdx30BaseUri}/Package/${idx + 1}`);
    const spdx30Json: Record<string, unknown> = {
      '@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld',
      '@graph': [
        {
          type: 'CreationInfo',
          spdxId: spdx30CreationInfoId,
          created: generatedAt,
          createdBy: [`${spdx30BaseUri}/Tool/WinHood-4.4.0`],
          specVersion: '3.0.1',
        },
        {
          type: 'SpdxDocument',
          spdxId: spdx30DocId,
          name: `${software.name}-${software.version}-sbom`,
          creationInfo: spdx30CreationInfoId,
          rootElement: spdx30PkgIds,
        },
        ...components.map((c, idx) => ({
          type: 'software_Package',
          spdxId: spdx30PkgIds[idx],
          creationInfo: spdx30CreationInfoId,
          name: c.name,
          software_packageVersion: c.version,
          software_packageUrl: c.purl,
          software_downloadLocation: 'NOASSERTION',
          ...(c.sha256
            ? {
                verifiedUsing: [
                  {
                    type: 'Hash',
                    algorithm: 'sha256',
                    hashValue: c.sha256,
                  },
                ],
              }
            : {}),
          comment: `declaredLicense=${c.license && c.license !== 'UNKNOWN' ? c.license : 'NOASSERTION'}; dependencyScope=${c.dependencyScope}; licenseProvenance=${c.licenseProvenance || 'UNVERIFIED'}`,
        })),
        ...(spdx30PkgIds.length > 0
          ? [
              {
                type: 'Relationship',
                spdxId: `${spdx30BaseUri}/Relationship/Contains`,
                creationInfo: spdx30CreationInfoId,
                relationshipType: 'contains',
                from: spdx30DocId,
                to: spdx30PkgIds,
              },
            ]
          : []),
      ],
    };

    const cyclonedxSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(cyclonedx15Json))
      .digest('hex');
    const cyclonedx17Sha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(cyclonedx17Json))
      .digest('hex');
    const spdxSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(spdx23Json))
      .digest('hex');
    const spdx30Sha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(spdx30Json))
      .digest('hex');

    const bundle: SbomDocumentBundle = {
      softwareId: software.id,
      softwareName: software.name,
      softwareVersion: software.version,
      generatedAt,
      sourceMethod: 'LOCKFILE_AND_MANIFEST_PARSER',
      componentsCount: components.length,
      directCount,
      transitiveCount,
      devCount,
      optionalCount,
      unresolvedDependenciesCount,
      unknownLicenseCount,
      transitiveCoverageComplete,
      lockfilesDetected,
      supportedFormats: ['cyclonedx-1.5', 'cyclonedx-1.7', 'spdx-2.3', 'spdx-3.0'],
      components,
      cyclonedx15Json,
      cyclonedx17Json,
      spdx23Json,
      spdx30Json,
      cyclonedxSha256,
      cyclonedx17Sha256,
      spdxSha256,
      spdx30Sha256,
      deterministicMode,
    };

    bundle.structuralValidation = SbomGenerator.validateSbomBundle(bundle);

    if (options?.signSbom !== false) {
      bundle.signature = SbomGenerator.signSbomBundle(bundle, generatedAt);
    }

    return bundle;
  }

  public static signSbomBundle(bundle: SbomDocumentBundle, signedAt?: string): SbomSignatureRecord {
    const payloadSha256 = crypto
      .createHash('sha256')
      .update(
        JSON.stringify({
          softwareId: bundle.softwareId,
          softwareVersion: bundle.softwareVersion,
          cyclonedxSha256: bundle.cyclonedxSha256,
          spdxSha256: bundle.spdxSha256,
          componentsCount: bundle.componentsCount,
        }),
        'utf8'
      )
      .digest('hex');

    const hmacKey = KeyManagementService.getActiveEvidenceHmacKey();
    const hmacSignature = crypto
      .createHmac('sha256', hmacKey.secret)
      .update(payloadSha256, 'utf8')
      .digest('hex');

    let ed25519Signature: string | undefined;
    let ed25519PublicKeyPem: string | undefined;
    let ed25519KeyId: string | undefined;

    try {
      const edKey = KeyManagementService.getActiveEvidenceEd25519Key();
      ed25519Signature = crypto
        .sign(null, Buffer.from(payloadSha256, 'utf8'), edKey.privateKeyPem)
        .toString('base64');
      ed25519PublicKeyPem = edKey.publicKeyPem;
      ed25519KeyId = edKey.keyId;
    } catch {
      // Omit asymmetric signature if unavailable
    }

    return {
      algorithm: ed25519Signature ? 'HMAC-SHA256+ED25519' : 'HMAC-SHA256',
      signedAt: signedAt || new Date().toISOString(),
      payloadSha256,
      hmacSignature,
      signingKeyId: hmacKey.keyId,
      ed25519Signature,
      ed25519PublicKeyPem,
      ed25519KeyId,
    };
  }

  public static verifySbomSignature(bundle: SbomDocumentBundle): {
    valid: boolean;
    reason: string;
    ed25519Valid: boolean | null;
  } {
    if (!bundle.signature) {
      return { valid: false, reason: 'SBOM_SIGNATURE_MISSING', ed25519Valid: null };
    }
    if (Array.isArray(bundle.components) && bundle.components.length !== bundle.componentsCount) {
      return { valid: false, reason: 'SBOM_COMPONENTS_COUNT_MISMATCH', ed25519Valid: null };
    }
    const recomputedCdx = crypto
      .createHash('sha256')
      .update(JSON.stringify(bundle.cyclonedx15Json))
      .digest('hex');
    const recomputedSpdx = crypto
      .createHash('sha256')
      .update(JSON.stringify(bundle.spdx23Json))
      .digest('hex');
    if (recomputedCdx !== bundle.cyclonedxSha256 || recomputedSpdx !== bundle.spdxSha256) {
      return { valid: false, reason: 'SBOM_DOCUMENT_HASH_MISMATCH', ed25519Valid: null };
    }

    const expectedPayloadSha = crypto
      .createHash('sha256')
      .update(
        JSON.stringify({
          softwareId: bundle.softwareId,
          softwareVersion: bundle.softwareVersion,
          cyclonedxSha256: bundle.cyclonedxSha256,
          spdxSha256: bundle.spdxSha256,
          componentsCount: bundle.componentsCount,
        }),
        'utf8'
      )
      .digest('hex');

    if (expectedPayloadSha !== bundle.signature.payloadSha256) {
      return { valid: false, reason: 'SBOM_PAYLOAD_HASH_MISMATCH', ed25519Valid: null };
    }

    const hmacSecret = KeyManagementService.getEvidenceSecretByKeyId(bundle.signature.signingKeyId);
    if (!hmacSecret) {
      return { valid: false, reason: 'SBOM_HMAC_KEY_NOT_FOUND', ed25519Valid: null };
    }

    const expectedHmac = crypto
      .createHmac('sha256', hmacSecret)
      .update(expectedPayloadSha, 'utf8')
      .digest('hex');
    const a = Buffer.from(expectedHmac, 'hex');
    const b = Buffer.from(bundle.signature.hmacSignature, 'hex');
    const hmacOk = a.length === b.length && crypto.timingSafeEqual(a, b);
    if (!hmacOk) {
      return { valid: false, reason: 'SBOM_HMAC_INVALID', ed25519Valid: null };
    }

    let ed25519Valid: boolean | null = null;
    if (bundle.signature.ed25519Signature) {
      const trustCheck = KeyManagementService.verifyTrustedEd25519PublicKey(
        bundle.signature.ed25519KeyId,
        bundle.signature.ed25519PublicKeyPem,
        bundle.signature.signedAt
      );
      if (!trustCheck.trusted || !trustCheck.publicKeyPem) {
        return { valid: false, reason: 'SBOM_ED25519_KEY_NOT_FOUND', ed25519Valid: false };
      }
      ed25519Valid = crypto.verify(
        null,
        Buffer.from(expectedPayloadSha, 'utf8'),
        trustCheck.publicKeyPem,
        Buffer.from(bundle.signature.ed25519Signature, 'base64')
      );
      if (!ed25519Valid) {
        return { valid: false, reason: 'SBOM_ED25519_INVALID', ed25519Valid: false };
      }
    }

    return { valid: true, reason: 'SBOM_SIGNATURE_VERIFIED', ed25519Valid };
  }

  public static extractComponents(
    filesMap: Record<string, string>,
    options?: { strictLicenseProvenance?: boolean }
  ): SbomComponentRecord[] {
    return SbomGenerator.extractComponentsWithMetadata(filesMap, options).components;
  }

  public static extractComponentsWithMetadata(
    filesMap: Record<string, string>,
    options?: { strictLicenseProvenance?: boolean }
  ): {
    components: SbomComponentRecord[];
    lockfilesDetected: string[];
    transitiveCoverageComplete: boolean;
  } {
    const components: SbomComponentRecord[] = [];
    const seen = new Set<string>();
    const lockfilesDetected: string[] = [];
    const sortedEntries = Object.entries(filesMap).sort(([a], [b]) => a.localeCompare(b));
    const strictProvenance = Boolean(options?.strictLicenseProvenance);

    const computeComponentDigest = (
      ecosystem: string,
      name: string,
      version: string,
      manifestDigest: string,
      integrityRaw?: string
    ): string => {
      if (integrityRaw && /^sha(512|256)-/i.test(integrityRaw)) {
        return crypto.createHash('sha256').update(integrityRaw, 'utf8').digest('hex');
      }
      return crypto
        .createHash('sha256')
        .update(`${ecosystem}:${name}@${version}:${manifestDigest}`, 'utf8')
        .digest('hex');
    };

    const addComponent = (rec: SbomComponentRecord) => {
      const key = `${rec.ecosystem}:${rec.name}@${rec.version}`;
      if (seen.has(key)) return;
      seen.add(key);
      components.push(rec);
    };

    // 1. package.json (direct, dev, and optional dependencies)
    const directNpmScopes = new Map<string, 'DIRECT' | 'DEV' | 'OPTIONAL'>();
    let hasManifestWithoutLockfile = false;
    for (const [filePath, content] of sortedEntries) {
      if (filePath.endsWith('package.json')) {
        hasManifestWithoutLockfile = true;
        const manifestDigest = crypto.createHash('sha256').update(content, 'utf8').digest('hex').slice(0, 16);
        try {
          const pkg = JSON.parse(content);
          const rootLicense = typeof pkg.license === 'string' ? pkg.license : 'UNKNOWN';
          const depGroups: Array<{ map: Record<string, unknown>; scope: 'DIRECT' | 'DEV' | 'OPTIONAL' }> = [
            { map: pkg.dependencies || {}, scope: 'DIRECT' },
            { map: pkg.optionalDependencies || {}, scope: 'OPTIONAL' },
            { map: pkg.devDependencies || {}, scope: 'DEV' },
          ];
          for (const grp of depGroups) {
            for (const [name, rawVer] of Object.entries(grp.map).sort(([a], [b]) => a.localeCompare(b))) {
              if (!directNpmScopes.has(name)) {
                directNpmScopes.set(name, grp.scope);
              }
              const ver = String(rawVer).replace(/^[\^~>=< ]+/, '') || '0.0.0';
              const licInfo = resolvePackageSpdxLicenseWithProvenance(name, undefined, rootLicense, {
                strictProvenance,
              });
              addComponent({
                bomRef: `pkg:npm/${name}@${ver}`,
                name,
                version: ver,
                purl: `pkg:npm/${name.replace('@', '%40')}@${ver}`,
                ecosystem: 'npm',
                license: licInfo.license,
                licenseProvenance: licInfo.provenance,
                dependencyScope: grp.scope === 'DEV' || grp.scope === 'OPTIONAL' ? 'DIRECT' : grp.scope,
                manifestFile: filePath,
                sha256: computeComponentDigest('npm', name, ver, manifestDigest),
              });
            }
          }
        } catch {
          // Ignore malformed package.json
        }
      }
    }

    // 2. npm package-lock.json & npm-shrinkwrap.json
    for (const [filePath, content] of sortedEntries) {
      if (filePath.endsWith('package-lock.json') || filePath.endsWith('npm-shrinkwrap.json')) {
        lockfilesDetected.push(filePath);
        const manifestDigest = crypto.createHash('sha256').update(content, 'utf8').digest('hex').slice(0, 16);
        try {
          const lock = JSON.parse(content);
          if (lock.packages && typeof lock.packages === 'object') {
            for (const [pkgPath, meta] of Object.entries<any>(lock.packages).sort(([a], [b]) => a.localeCompare(b))) {
              if (!pkgPath || pkgPath === '') continue;
              const name = pkgPath.replace(/^.*node_modules\//, '');
              const ver = String(meta?.version || '0.0.0');
              const licInfo = resolvePackageSpdxLicenseWithProvenance(
                name,
                typeof meta?.license === 'string' ? meta.license : undefined,
                undefined,
                { strictProvenance }
              );
              const scope = directNpmScopes.has(name) ? 'DIRECT' : 'TRANSITIVE';
              const existingIdx = components.findIndex(
                (c) => c.ecosystem === 'npm' && c.name === name && c.version === ver
              );
              const computedSha = computeComponentDigest('npm', name, ver, manifestDigest, meta?.integrity);
              if (existingIdx >= 0) {
                if (licInfo.license !== 'UNKNOWN' && licInfo.license !== 'NOASSERTION') {
                  components[existingIdx]!.license = licInfo.license;
                  components[existingIdx]!.licenseProvenance = licInfo.provenance;
                }
                components[existingIdx]!.sha256 = computedSha;
                continue;
              }
              addComponent({
                bomRef: `pkg:npm/${name}@${ver}`,
                name,
                version: ver,
                purl: `pkg:npm/${name.replace('@', '%40')}@${ver}`,
                ecosystem: 'npm',
                license: licInfo.license,
                licenseProvenance: licInfo.provenance,
                dependencyScope: scope,
                manifestFile: filePath,
                sha256: computedSha,
              });
            }
          }
        } catch {
          // Ignore malformed lockfile
        }
      }

      const addNpmLockfileComponent = (
        name: string,
        ver: string,
        manifestDigest: string,
        integrity?: string
      ) => {
        const licInfo = resolvePackageSpdxLicenseWithProvenance(name, undefined, undefined, {
          strictProvenance,
        });
        addComponent({
          bomRef: `pkg:npm/${name}@${ver}`,
          name,
          version: ver,
          purl: `pkg:npm/${name.replace('@', '%40')}@${ver}`,
          ecosystem: 'npm',
          license: licInfo.license,
          licenseProvenance: licInfo.provenance,
          dependencyScope: directNpmScopes.has(name) ? 'DIRECT' : 'TRANSITIVE',
          manifestFile: filePath,
          sha256: computeComponentDigest('npm', name, ver, manifestDigest, integrity),
        });
      };

      // 3. yarn.lock (Classic v1 & Berry v2+)
      if (filePath.endsWith('yarn.lock')) {
        lockfilesDetected.push(filePath);
        const manifestDigest = crypto.createHash('sha256').update(content, 'utf8').digest('hex').slice(0, 16);
        const blocks = content.split(/\r?\n\r?\n+/);
        for (const block of blocks) {
          const lines = block.split(/\r?\n/).map((l) => l.trim());
          const header = lines.find((l) => l && !l.startsWith('#') && l.endsWith(':'));
          if (!header) continue;
          const firstSpec = header.replace(/:$/, '').split(',')[0]!.replace(/^["']|["']$/g, '').trim();
          const atIdx = firstSpec.lastIndexOf('@');
          if (atIdx <= 0) continue;
          const name = firstSpec.slice(0, atIdx).replace(/@npm$/, '');
          const verLine = lines.find((l) => /^version[:\s]/i.test(l));
          if (!verLine) continue;
          const verMatch = verLine.match(/version[:\s]+["']?([0-9a-zA-Z._+-]+)["']?/i);
          if (!verMatch) continue;
          const ver = verMatch[1]!;
          const intLine = lines.find((l) => /^(integrity|checksum)[:\s]/i.test(l));
          const integrity = intLine ? intLine.split(/[:\s]+/).slice(1).join('').replace(/["']/g, '') : undefined;
          addNpmLockfileComponent(name, ver, manifestDigest, integrity);
        }
      }

      // 4. pnpm-lock.yaml (v6/v9 package entries)
      if (filePath.endsWith('pnpm-lock.yaml')) {
        lockfilesDetected.push(filePath);
        const manifestDigest = crypto.createHash('sha256').update(content, 'utf8').digest('hex').slice(0, 16);
        for (const rawLine of content.split(/\r?\n/)) {
          const trimmed = rawLine.trim();
          // Matches '/lodash@4.17.21:' or 'lodash@4.17.21:' or "'@babel/parser@7.26.0':"
          const m = trimmed.match(/^['"]?\/?(@?[a-zA-Z0-9._/-]+)@([0-9]+\.[0-9]+\.[0-9]+[^('":\s]*)/);
          if (m && m[1] && m[2]) {
            addNpmLockfileComponent(m[1], m[2], manifestDigest);
          }
        }
      }

      // 5. bun.lock (JSONC lockfile in analyzed external projects)
      if (filePath.endsWith('bun.lock')) {
        lockfilesDetected.push(filePath);
        const manifestDigest = crypto.createHash('sha256').update(content, 'utf8').digest('hex').slice(0, 16);
        try {
          const cleanJson = content.replace(/,\s*([\]}])/g, '$1');
          const parsedBun = JSON.parse(cleanJson);
          if (parsedBun?.packages && typeof parsedBun.packages === 'object') {
            for (const [pkgKey, arr] of Object.entries<any>(parsedBun.packages)) {
              const firstTuple = Array.isArray(arr) && typeof arr[0] === 'string' ? arr[0] : '';
              const atIdx = firstTuple.lastIndexOf('@');
              const name = atIdx > 0 ? firstTuple.slice(0, atIdx) : pkgKey;
              const ver = atIdx > 0 ? firstTuple.slice(atIdx + 1) : '0.0.0';
              const integrity = Array.isArray(arr) && typeof arr[3] === 'string' ? arr[3] : undefined;
              addNpmLockfileComponent(name, ver, manifestDigest, integrity);
            }
          }
        } catch {
          // Ignore malformed bun.lock
        }
      }
    }

    // 6. Python, Go, Rust, Maven, NuGet
    for (const [filePath, content] of sortedEntries) {
      const manifestDigest = crypto.createHash('sha256').update(content, 'utf8').digest('hex').slice(0, 16);
      const addPypiManifestComponent = (name: string, ver: string) => {
        addComponent({
          bomRef: `pkg:pypi/${name}@${ver}`,
          name,
          version: ver,
          purl: `pkg:pypi/${name}@${ver}`,
          ecosystem: 'pypi',
          license: 'NOASSERTION',
          licenseProvenance: 'UNVERIFIED',
          dependencyScope: 'DIRECT',
          manifestFile: filePath,
          sha256: computeComponentDigest('pypi', name, ver, manifestDigest),
        });
      };

      if (filePath.endsWith('requirements.txt')) {
        lockfilesDetected.push(filePath);
        for (const rawLine of content.split(/\r?\n/)) {
          const line = rawLine.trim();
          if (!line || line.startsWith('#') || line.startsWith('-')) continue;
          const m = line.match(/^([a-zA-Z0-9._-]+)\s*(?:==|>=|~=)?\s*([a-zA-Z0-9._-]+)?/);
          if (m) {
            addPypiManifestComponent(m[1]!, m[2] || 'UNPINNED');
          }
        }
      }

      if (filePath.endsWith('pyproject.toml')) {
        hasManifestWithoutLockfile = true;
        const depMatch = content.match(/dependencies\s*=\s*\[([\s\S]*?)\]/);
        if (depMatch) {
          for (const rawItem of depMatch[1]!.split(',')) {
            const item = rawItem.replace(/['"\s]/g, '');
            const m = item.match(/^([a-zA-Z0-9._-]+)(?:==|>=|~=)?([a-zA-Z0-9._-]+)?/);
            if (m && m[1]) {
              addPypiManifestComponent(m[1], m[2] || 'UNPINNED');
            }
          }
        }
      }

      if (filePath.endsWith('go.mod')) {
        lockfilesDetected.push(filePath);
        for (const rawLine of content.split(/\r?\n/)) {
          const line = rawLine.trim();
          const m = line.match(/^([^\s/]+\/[^\s]+)\s+(v[0-9.]+[^\s]*)(?:\s+\/\/\s*(indirect))?/);
          if (m) {
            const name = m[1]!;
            const ver = m[2]!;
            const isIndirect = Boolean(m[3]);
            addComponent({
              bomRef: `pkg:golang/${name}@${ver}`,
              name,
              version: ver,
              purl: `pkg:golang/${name}@${ver}`,
              ecosystem: 'golang',
              license: 'NOASSERTION',
              licenseProvenance: 'UNVERIFIED',
              dependencyScope: isIndirect ? 'TRANSITIVE' : 'DIRECT',
              manifestFile: filePath,
              sha256: computeComponentDigest('golang', name, ver, manifestDigest),
            });
          }
        }
      }

      if (filePath.endsWith('Cargo.toml')) {
        hasManifestWithoutLockfile = true;
        let inDeps = false;
        for (const rawLine of content.split(/\r?\n/)) {
          const line = rawLine.trim();
          if (line.startsWith('[')) {
            inDeps = /^\[(dependencies|dev-dependencies)\]/i.test(line);
            continue;
          }
          if (inDeps) {
            const m = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
            if (m) {
              const name = m[1]!;
              const ver = m[2]!;
              addComponent({
                bomRef: `pkg:cargo/${name}@${ver}`,
                name,
                version: ver,
                purl: `pkg:cargo/${name}@${ver}`,
                ecosystem: 'cargo',
                license: 'NOASSERTION',
                licenseProvenance: 'UNVERIFIED',
                dependencyScope: 'DIRECT',
                manifestFile: filePath,
                sha256: computeComponentDigest('cargo', name, ver, manifestDigest),
              });
            }
          }
        }
      }

      if (filePath.endsWith('Cargo.lock')) {
        lockfilesDetected.push(filePath);
        const pkgBlocks = content.split(/\[\[package\]\]/);
        for (const block of pkgBlocks.slice(1)) {
          const nameM = block.match(/name\s*=\s*"([^"]+)"/);
          const verM = block.match(/version\s*=\s*"([^"]+)"/);
          const chkM = block.match(/checksum\s*=\s*"([^"]+)"/);
          if (nameM && verM) {
            const name = nameM[1]!;
            const ver = verM[1]!;
            addComponent({
              bomRef: `pkg:cargo/${name}@${ver}`,
              name,
              version: ver,
              purl: `pkg:cargo/${name}@${ver}`,
              ecosystem: 'cargo',
              license: 'NOASSERTION',
              licenseProvenance: 'UNVERIFIED',
              dependencyScope: 'TRANSITIVE',
              manifestFile: filePath,
              sha256: chkM?.[1] || computeComponentDigest('cargo', name, ver, manifestDigest),
            });
          }
        }
      }

      if (filePath.endsWith('pom.xml')) {
        hasManifestWithoutLockfile = true;
        const depRegex = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>(?:[\s\S]*?<version>([^<]+)<\/version>)?[\s\S]*?<\/dependency>/g;
        for (const m of content.matchAll(depRegex)) {
          const name = `${m[1]!.trim()}:${m[2]!.trim()}`;
          const ver = (m[3] || 'MANAGED').trim();
          addComponent({
            bomRef: `pkg:maven/${m[1]!.trim()}/${m[2]!.trim()}@${ver}`,
            name,
            version: ver,
            purl: `pkg:maven/${m[1]!.trim()}/${m[2]!.trim()}@${ver}`,
            ecosystem: 'maven',
            license: 'NOASSERTION',
            licenseProvenance: 'UNVERIFIED',
            dependencyScope: 'DIRECT',
            manifestFile: filePath,
            sha256: computeComponentDigest('maven', name, ver, manifestDigest),
          });
        }
      }

      if (filePath.endsWith('poetry.lock')) {
        lockfilesDetected.push(filePath);
        const pkgBlocks = content.split(/\[\[package\]\]/);
        for (const block of pkgBlocks.slice(1)) {
          const nameM = block.match(/name\s*=\s*"([^"]+)"/);
          const verM = block.match(/version\s*=\s*"([^"]+)"/);
          if (nameM && verM) {
            const name = nameM[1]!;
            const ver = verM[1]!;
            addComponent({
              bomRef: `pkg:pypi/${name}@${ver}`,
              name,
              version: ver,
              purl: `pkg:pypi/${name}@${ver}`,
              ecosystem: 'pypi',
              license: 'NOASSERTION',
              licenseProvenance: 'UNVERIFIED',
              dependencyScope: 'TRANSITIVE',
              dependencyPath: `${filePath} > ${name}@${ver}`,
              versionResolutionState: 'RESOLVED_LOCKED',
              manifestFile: filePath,
              sha256: computeComponentDigest('pypi', name, ver, manifestDigest),
            });
          }
        }
      }

      if (filePath.endsWith('Pipfile.lock')) {
        lockfilesDetected.push(filePath);
        try {
          const pipLock = JSON.parse(content);
          for (const section of ['default', 'develop'] as const) {
            const group = pipLock?.[section];
            if (!group || typeof group !== 'object') continue;
            for (const [name, meta] of Object.entries<any>(group)) {
              const ver = String(meta?.version || 'UNPINNED').replace(/^==/, '');
              const firstHash = Array.isArray(meta?.hashes) ? String(meta.hashes[0] || '') : undefined;
              addComponent({
                bomRef: `pkg:pypi/${name}@${ver}`,
                name,
                version: ver,
                purl: `pkg:pypi/${name}@${ver}`,
                ecosystem: 'pypi',
                license: 'NOASSERTION',
                licenseProvenance: 'UNVERIFIED',
                dependencyScope: section === 'develop' ? 'DEV' : 'DIRECT',
                dependencyPath: `${filePath} (${section}) > ${name}@${ver}`,
                versionResolutionState: ver === 'UNPINNED' ? 'UNRESOLVED' : 'RESOLVED_LOCKED',
                manifestFile: filePath,
                sha256: computeComponentDigest('pypi', name, ver, manifestDigest, firstHash),
              });
            }
          }
        } catch {
          // Ignore malformed Pipfile.lock
        }
      }

      if (filePath.endsWith('go.sum')) {
        lockfilesDetected.push(filePath);
        for (const rawLine of content.split(/\r?\n/)) {
          const line = rawLine.trim();
          if (!line) continue;
          const parts = line.split(/\s+/);
          if (parts.length < 3) continue;
          const name = parts[0]!;
          const rawVer = parts[1]!;
          if (rawVer.endsWith('/go.mod')) continue;
          const ver = rawVer;
          addComponent({
            bomRef: `pkg:golang/${name}@${ver}`,
            name,
            version: ver,
            purl: `pkg:golang/${name}@${ver}`,
            ecosystem: 'golang',
            license: 'NOASSERTION',
            licenseProvenance: 'UNVERIFIED',
            dependencyScope: 'TRANSITIVE',
            dependencyPath: `${filePath} > ${name}@${ver}`,
            versionResolutionState: 'RESOLVED_LOCKED',
            manifestFile: filePath,
            sha256: computeComponentDigest('golang', name, ver, manifestDigest, parts[2]),
          });
        }
      }

      if (
        filePath.endsWith('build.gradle') ||
        filePath.endsWith('build.gradle.kts') ||
        filePath.endsWith('gradle.lockfile')
      ) {
        const isLockfile = filePath.endsWith('gradle.lockfile');
        if (isLockfile) {
          lockfilesDetected.push(filePath);
          for (const rawLine of content.split(/\r?\n/)) {
            const line = rawLine.trim();
            if (!line || line.startsWith('#') || line.startsWith('empty=')) continue;
            const coord = line.split('=')[0] || '';
            const segs = coord.split(':');
            if (segs.length >= 3) {
              const group = segs[0]!.trim();
              const artifact = segs[1]!.trim();
              const ver = segs[2]!.trim();
              const name = `${group}:${artifact}`;
              addComponent({
                bomRef: `pkg:maven/${group}/${artifact}@${ver}`,
                name,
                version: ver,
                purl: `pkg:maven/${group}/${artifact}@${ver}`,
                ecosystem: 'maven',
                license: 'NOASSERTION',
                licenseProvenance: 'UNVERIFIED',
                dependencyScope: 'TRANSITIVE',
                dependencyPath: `${filePath} > ${name}@${ver}`,
                versionResolutionState: 'RESOLVED_LOCKED',
                manifestFile: filePath,
                sha256: computeComponentDigest('maven', name, ver, manifestDigest),
              });
            }
          }
        } else {
          hasManifestWithoutLockfile = true;
          const gradleKeywords = [
            'implementation',
            'api',
            'compileOnly',
            'runtimeOnly',
            'testImplementation',
          ];
          for (const rawLine of content.split(/\r?\n/)) {
            const trimmed = rawLine.trim();
            const matchedKw = gradleKeywords.find(
              (kw) =>
                trimmed.startsWith(kw) &&
                trimmed.length > kw.length &&
                (trimmed[kw.length] === ' ' || trimmed[kw.length] === '\t' || trimmed[kw.length] === '(')
            );
            if (!matchedKw) continue;
            const quoteIdx = trimmed.search(/['"]/);
            if (quoteIdx < 0) continue;
            const quoteChar = trimmed[quoteIdx]!;
            const closeQuoteIdx = trimmed.indexOf(quoteChar, quoteIdx + 1);
            if (closeQuoteIdx <= quoteIdx + 1) continue;
            const coord = trimmed.slice(quoteIdx + 1, closeQuoteIdx);
            const parts = coord.split(':');
            if (parts.length !== 3) continue;
            const group = parts[0]!.trim();
            const artifact = parts[1]!.trim();
            const ver = parts[2]!.trim();
            if (!group || !artifact || !ver) continue;
            const name = `${group}:${artifact}`;
            addComponent({
              bomRef: `pkg:maven/${group}/${artifact}@${ver}`,
              name,
              version: ver,
              purl: `pkg:maven/${group}/${artifact}@${ver}`,
              ecosystem: 'maven',
              license: 'NOASSERTION',
              licenseProvenance: 'UNVERIFIED',
              dependencyScope: 'DIRECT',
              dependencyPath: `${filePath} > ${name}@${ver}`,
              versionResolutionState: ver.includes('$') ? 'UNRESOLVED' : 'DECLARED_RANGE',
              manifestFile: filePath,
              sha256: computeComponentDigest('maven', name, ver, manifestDigest),
            });
          }
        }
      }

      if (filePath.endsWith('packages.lock.json')) {
        lockfilesDetected.push(filePath);
        try {
          const nugetLock = JSON.parse(content);
          const depsByTfm = nugetLock?.dependencies;
          if (depsByTfm && typeof depsByTfm === 'object') {
            for (const [tfm, pkgs] of Object.entries<any>(depsByTfm)) {
              if (!pkgs || typeof pkgs !== 'object') continue;
              for (const [name, meta] of Object.entries<any>(pkgs)) {
                const ver = String(meta?.resolved || meta?.requested || 'UNPINNED');
                const scope =
                  String(meta?.type || '').toLowerCase() === 'direct' ? 'DIRECT' : 'TRANSITIVE';
                addComponent({
                  bomRef: `pkg:nuget/${name}@${ver}`,
                  name,
                  version: ver,
                  purl: `pkg:nuget/${name}@${ver}`,
                  ecosystem: 'nuget',
                  license: 'NOASSERTION',
                  licenseProvenance: 'UNVERIFIED',
                  dependencyScope: scope,
                  dependencyPath: `${filePath} (${tfm}) > ${name}@${ver}`,
                  versionResolutionState: meta?.resolved ? 'RESOLVED_LOCKED' : 'UNRESOLVED',
                  manifestFile: filePath,
                  sha256: computeComponentDigest('nuget', name, ver, manifestDigest, meta?.contentHash),
                });
              }
            }
          }
        } catch {
          // Ignore malformed packages.lock.json
        }
      }

      if (filePath.toLowerCase().endsWith('.csproj')) {
        hasManifestWithoutLockfile = true;
        const pkgRef = /<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/g;
        for (const m of content.matchAll(pkgRef)) {
          const name = m[1]!;
          const ver = m[2]!;
          addComponent({
            bomRef: `pkg:nuget/${name}@${ver}`,
            name,
            version: ver,
            purl: `pkg:nuget/${name}@${ver}`,
            ecosystem: 'nuget',
            license: 'NOASSERTION',
            licenseProvenance: 'UNVERIFIED',
            dependencyScope: 'DIRECT',
            dependencyPath: `${filePath} > ${name}@${ver}`,
            versionResolutionState: 'DECLARED_RANGE',
            manifestFile: filePath,
            sha256: computeComponentDigest('nuget', name, ver, manifestDigest),
          });
        }
      }
    }

    components.sort((a, b) => a.bomRef.localeCompare(b.bomRef));
    const transitiveCoverageComplete =
      lockfilesDetected.length > 0 || !hasManifestWithoutLockfile;

    return {
      components,
      lockfilesDetected,
      transitiveCoverageComplete,
    };
  }
}
