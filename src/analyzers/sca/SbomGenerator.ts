import crypto from 'node:crypto';
import { KeyManagementService } from '../../security/KeyManagementService';
import type {
  SbomComponentRecord,
  SbomDocumentBundle,
  SbomSignatureRecord,
  Software,
} from '../../types/benchmark';

function deterministicUuidFromSeed(seed: string): string {
  const hex = crypto.createHash('sha256').update(seed, 'utf8').digest('hex').slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

/**
 * SbomGenerator (P1 + Cryptographic Signing + Per-Component SHA-256 + Deterministic Mode)
 * Generates CycloneDX 1.5 and SPDX 2.3 SBOM documents directly from package manifests and lockfiles:
 * package.json, package-lock.json, requirements.txt, pyproject.toml, pom.xml, go.mod, Cargo.toml, *.csproj
 */
export class SbomGenerator {
  public static generateFromSoftware(
    software: Software,
    options?: {
      deterministicTimestamp?: string;
      signSbom?: boolean;
    }
  ): SbomDocumentBundle {
    const filesMap = software.sourceFilesContent || {};
    const components = SbomGenerator.extractComponents(filesMap);
    const deterministicMode = Boolean(options?.deterministicTimestamp);
    const generatedAt = options?.deterministicTimestamp || new Date().toISOString();

    const directCount = components.filter((c) => c.dependencyScope === 'DIRECT').length;
    const transitiveCount = components.filter((c) => c.dependencyScope === 'TRANSITIVE').length;
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
            version: '4.3.0',
          },
        ],
        component: {
          type: 'application',
          name: software.name,
          version: software.version,
          'bom-ref': `app:${software.id}@${software.version}`,
        },
      },
      components: components.map((c) => ({
        type: 'library',
        'bom-ref': c.bomRef,
        name: c.name,
        version: c.version,
        purl: c.purl,
        scope: c.dependencyScope === 'DIRECT' ? 'required' : 'optional',
        hashes: c.sha256 ? [{ alg: 'SHA-256', content: c.sha256 }] : [],
        licenses: c.license && c.license !== 'UNKNOWN' ? [{ license: { id: c.license } }] : [],
        properties: [
          { name: 'winhood:dependencyScope', value: c.dependencyScope },
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
        creators: ['Tool: WinHood SBOM Generator-4.3.0'],
      },
      packages: components.map((c, idx) => ({
        SPDXID: `SPDXRef-Package-${idx + 1}`,
        name: c.name,
        versionInfo: c.version,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        checksums: c.sha256 ? [{ algorithm: 'SHA256', checksumValue: c.sha256 }] : [],
        licenseDeclared: c.license || 'NOASSERTION',
        externalRefs: [
          {
            referenceCategory: 'PACKAGE-MANAGER',
            referenceType: 'purl',
            referenceLocator: c.purl,
          },
        ],
        comment: `dependencyScope=${c.dependencyScope}; manifest=${c.manifestFile}`,
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
      components,
      cyclonedx15Json,
      spdx23Json,
      cyclonedxSha256,
      spdxSha256,
      deterministicMode,
    };

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

    const secret = KeyManagementService.getEvidenceSecretByKeyId(bundle.signature.signingKeyId);
    if (!secret) {
      return { valid: false, reason: 'SBOM_HMAC_KEY_NOT_FOUND', ed25519Valid: null };
    }

    const expectedHmac = crypto
      .createHmac('sha256', secret)
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
      const pubPem =
        (bundle.signature.ed25519KeyId
          ? KeyManagementService.getEd25519PublicKeyByKeyId(bundle.signature.ed25519KeyId)
          : null) || bundle.signature.ed25519PublicKeyPem;
      if (!pubPem) {
        return { valid: false, reason: 'SBOM_ED25519_KEY_NOT_FOUND', ed25519Valid: false };
      }
      ed25519Valid = crypto.verify(
        null,
        Buffer.from(expectedPayloadSha, 'utf8'),
        pubPem,
        Buffer.from(bundle.signature.ed25519Signature, 'base64')
      );
      if (!ed25519Valid) {
        return { valid: false, reason: 'SBOM_ED25519_INVALID', ed25519Valid: false };
      }
    }

    return { valid: true, reason: 'SBOM_SIGNATURE_VERIFIED', ed25519Valid };
  }

  public static extractComponents(filesMap: Record<string, string>): SbomComponentRecord[] {
    const components: SbomComponentRecord[] = [];
    const seen = new Set<string>();
    const sortedEntries = Object.entries(filesMap).sort(([a], [b]) => a.localeCompare(b));

    const computeComponentDigest = (
      ecosystem: string,
      name: string,
      version: string,
      manifestDigest: string,
      integrityRaw?: string
    ): string => {
      if (integrityRaw && /^sha512-/i.test(integrityRaw)) {
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

    // 1. package.json & package-lock.json (extracts both direct and transitive dependencies when present)
    const directNpmNames = new Set<string>();
    for (const [filePath, content] of sortedEntries) {
      if (filePath.endsWith('package.json')) {
        const manifestDigest = crypto.createHash('sha256').update(content, 'utf8').digest('hex').slice(0, 16);
        try {
          const pkg = JSON.parse(content);
          const rootLicense = typeof pkg.license === 'string' ? pkg.license : 'UNKNOWN';
          const allDirect = {
            ...(pkg.dependencies || {}),
            ...(pkg.devDependencies || {}),
          };
          for (const [name, rawVer] of Object.entries(allDirect).sort(([a], [b]) => a.localeCompare(b))) {
            directNpmNames.add(name);
            const ver = String(rawVer).replace(/^[\^~>=< ]+/, '') || '0.0.0';
            addComponent({
              bomRef: `pkg:npm/${name}@${ver}`,
              name,
              version: ver,
              purl: `pkg:npm/${name.replace('@', '%40')}@${ver}`,
              ecosystem: 'npm',
              license: rootLicense !== 'UNKNOWN' ? rootLicense : 'NOASSERTION',
              dependencyScope: 'DIRECT',
              manifestFile: filePath,
              sha256: computeComponentDigest('npm', name, ver, manifestDigest),
            });
          }
        } catch {
          // Ignore malformed package.json
        }
      }
    }

    for (const [filePath, content] of sortedEntries) {
      if (filePath.endsWith('package-lock.json')) {
        const manifestDigest = crypto.createHash('sha256').update(content, 'utf8').digest('hex').slice(0, 16);
        try {
          const lock = JSON.parse(content);
          if (lock.packages && typeof lock.packages === 'object') {
            for (const [pkgPath, meta] of Object.entries<any>(lock.packages).sort(([a], [b]) => a.localeCompare(b))) {
              if (!pkgPath || pkgPath === '') continue;
              const name = pkgPath.replace(/^.*node_modules\//, '');
              const ver = String(meta?.version || '0.0.0');
              const license = typeof meta?.license === 'string' ? meta.license : 'UNKNOWN';
              const scope = directNpmNames.has(name) ? 'DIRECT' : 'TRANSITIVE';
              const existingIdx = components.findIndex(
                (c) => c.ecosystem === 'npm' && c.name === name && c.version === ver
              );
              const computedSha = computeComponentDigest('npm', name, ver, manifestDigest, meta?.integrity);
              if (existingIdx >= 0) {
                if (license !== 'UNKNOWN') components[existingIdx]!.license = license;
                components[existingIdx]!.sha256 = computedSha;
                continue;
              }
              addComponent({
                bomRef: `pkg:npm/${name}@${ver}`,
                name,
                version: ver,
                purl: `pkg:npm/${name.replace('@', '%40')}@${ver}`,
                ecosystem: 'npm',
                license,
                dependencyScope: scope,
                manifestFile: filePath,
                sha256: computedSha,
              });
            }
          }
        } catch {
          // Ignore malformed package-lock.json
        }
      }
    }

    // 2. Python requirements.txt & pyproject.toml
    for (const [filePath, content] of sortedEntries) {
      const manifestDigest = crypto.createHash('sha256').update(content, 'utf8').digest('hex').slice(0, 16);

      if (filePath.endsWith('requirements.txt')) {
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
              license: 'UNKNOWN',
              dependencyScope: 'DIRECT',
              manifestFile: filePath,
              sha256: computeComponentDigest('pypi', name, ver, manifestDigest),
            });
          }
        }
      }

      if (filePath.endsWith('pyproject.toml')) {
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
                license: 'UNKNOWN',
                dependencyScope: 'DIRECT',
                manifestFile: filePath,
                sha256: computeComponentDigest('pypi', name, ver, manifestDigest),
              });
            }
          }
        }
      }

      // 3. Go go.mod
      if (filePath.endsWith('go.mod')) {
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
              license: 'UNKNOWN',
              dependencyScope: isIndirect ? 'TRANSITIVE' : 'DIRECT',
              manifestFile: filePath,
              sha256: computeComponentDigest('golang', name, ver, manifestDigest),
            });
          }
        }
      }

      // 4. Rust Cargo.toml
      if (filePath.endsWith('Cargo.toml')) {
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
                license: 'UNKNOWN',
                dependencyScope: 'DIRECT',
                manifestFile: filePath,
                sha256: computeComponentDigest('cargo', name, ver, manifestDigest),
              });
            }
          }
        }
      }

      // 5. Java pom.xml
      if (filePath.endsWith('pom.xml')) {
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
            license: 'UNKNOWN',
            dependencyScope: 'DIRECT',
            manifestFile: filePath,
            sha256: computeComponentDigest('maven', name, ver, manifestDigest),
          });
        }
      }

      // 6. .NET *.csproj
      if (filePath.toLowerCase().endsWith('.csproj')) {
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
            license: 'UNKNOWN',
            dependencyScope: 'DIRECT',
            manifestFile: filePath,
            sha256: computeComponentDigest('nuget', name, ver, manifestDigest),
          });
        }
      }
    }

    components.sort((a, b) => a.bomRef.localeCompare(b.bomRef));
    return components;
  }
}
