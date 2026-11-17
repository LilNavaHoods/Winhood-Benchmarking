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
    const nmPkgPath = path.resolve(process.cwd(), 'node_modules', normalizedName, 'package.json');
    if (fs.existsSync(nmPkgPath)) {
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

/**
 * SbomGenerator (Multi-Lockfile + Verifiable SPDX Provenance + CycloneDX 1.5 & SPDX 2.3 Validation)
 * Generates CycloneDX 1.5 and SPDX 2.3 SBOM documents directly from package manifests and lockfiles:
 * package.json, package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock,
 * requirements.txt, pyproject.toml, pom.xml, go.mod, Cargo.toml, Cargo.lock, *.csproj
 */
export class SbomGenerator {
  public static validateSbomBundle(bundle: SbomDocumentBundle): {
    cyclonedxValid: boolean;
    spdxValid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];
    const cdx = bundle.cyclonedx15Json as Record<string, any> | undefined;
    if (!cdx) {
      errors.push('CycloneDX 1.5 JSON document missing.');
    } else {
      if (cdx.bomFormat !== 'CycloneDX') errors.push('CycloneDX bomFormat must be "CycloneDX".');
      if (cdx.specVersion !== '1.5') errors.push('CycloneDX specVersion must be "1.5".');
      if (typeof cdx.serialNumber !== 'string' || !cdx.serialNumber.startsWith('urn:uuid:')) {
        errors.push('CycloneDX serialNumber must be a valid urn:uuid.');
      }
      if (!cdx.metadata?.timestamp || !cdx.metadata?.component?.name) {
        errors.push('CycloneDX metadata.timestamp and metadata.component.name are required.');
      }
      if (!Array.isArray(cdx.components)) {
        errors.push('CycloneDX components must be an array.');
      }
    }

    const spdx = bundle.spdx23Json as Record<string, any> | undefined;
    if (!spdx) {
      errors.push('SPDX 2.3 JSON document missing.');
    } else {
      if (spdx.spdxVersion !== 'SPDX-2.3') errors.push('SPDX spdxVersion must be "SPDX-2.3".');
      if (spdx.dataLicense !== 'CC0-1.0') errors.push('SPDX dataLicense must be "CC0-1.0".');
      if (spdx.SPDXID !== 'SPDXRef-DOCUMENT') errors.push('SPDX SPDXID must be "SPDXRef-DOCUMENT".');
      if (typeof spdx.documentNamespace !== 'string' || !spdx.documentNamespace.startsWith('https://')) {
        errors.push('SPDX documentNamespace must be a valid URI.');
      }
      if (!spdx.creationInfo?.created || !Array.isArray(spdx.creationInfo?.creators)) {
        errors.push('SPDX creationInfo.created and creators are required.');
      }
      if (!Array.isArray(spdx.packages)) {
        errors.push('SPDX packages must be an array.');
      }
    }

    const cyclonedxValid = !errors.some((e) => e.startsWith('CycloneDX'));
    const spdxValid = !errors.some((e) => e.startsWith('SPDX'));
    return { cyclonedxValid, spdxValid, errors };
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
    const serialSeed = JSON.stringify({
      softwareId: software.id,
      version: software.version,
      components: components.map((c) => `${c.bomRef}:${c.sha256 || ''}`),
    });
    const docUuid = deterministicMode ? deterministicUuidFromSeed(serialSeed) : crypto.randomUUID();

    const cyclonedx15Json: Record<string, unknown> = {
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
          'bom-ref': `app:${software.id}@${software.version}`,
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
      components: components.map((c) => ({
        type: 'library',
        'bom-ref': c.bomRef,
        name: c.name,
        version: c.version,
        purl: c.purl,
        scope:
          c.dependencyScope === 'DIRECT'
            ? 'required'
            : c.dependencyScope === 'OPTIONAL'
              ? 'optional'
              : 'optional',
        hashes: c.sha256 ? [{ alg: 'SHA-256', content: c.sha256 }] : [],
        licenses: c.license && c.license !== 'UNKNOWN' ? [{ license: { id: c.license } }] : [],
        properties: [
          { name: 'winhood:dependencyScope', value: c.dependencyScope },
          { name: 'winhood:licenseProvenance', value: c.licenseProvenance || 'UNVERIFIED' },
          { name: 'winhood:manifestFile', value: c.manifestFile },
          { name: 'winhood:ecosystem', value: c.ecosystem },
        ],
      })),
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

    const cyclonedxSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(cyclonedx15Json))
      .digest('hex');
    const spdxSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(spdx23Json))
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
      transitiveCoverageComplete,
      lockfilesDetected,
      components,
      cyclonedx15Json,
      spdx23Json,
      cyclonedxSha256,
      spdxSha256,
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
            const name = m[1];
            const ver = m[2];
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
              sha256: computeComponentDigest('npm', name, ver, manifestDigest),
            });
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

      if (filePath.endsWith('requirements.txt')) {
        lockfilesDetected.push(filePath);
        for (const rawLine of content.split(/\r?\n/)) {
          const line = rawLine.trim();
          if (!line || line.startsWith('#') || line.startsWith('-')) continue;
          const m = line.match(/^([a-zA-Z0-9._-]+)\s*(?:==|>=|~=)?\s*([a-zA-Z0-9._-]+)?/);
          if (m) {
            const name = m[1]!;
            const ver = m[2] || 'UNPINNED';
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
              const name = m[1];
              const ver = m[2] || 'UNPINNED';
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
