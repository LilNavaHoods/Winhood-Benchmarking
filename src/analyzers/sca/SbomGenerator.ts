import crypto from 'node:crypto';
import type { SbomComponentRecord, SbomDocumentBundle, Software } from '../../types/benchmark';

/**
 * SbomGenerator (P1)
 * Generates CycloneDX 1.5 and SPDX 2.3 SBOM documents directly from package manifests and lockfiles:
 * package.json, package-lock.json, requirements.txt, pyproject.toml, pom.xml, go.mod, Cargo.toml, *.csproj
 */
export class SbomGenerator {
  public static generateFromSoftware(software: Software): SbomDocumentBundle {
    const filesMap = software.sourceFilesContent || {};
    const components = SbomGenerator.extractComponents(filesMap);
    const generatedAt = new Date().toISOString();

    const directCount = components.filter((c) => c.dependencyScope === 'DIRECT').length;
    const transitiveCount = components.filter((c) => c.dependencyScope === 'TRANSITIVE').length;

    const cyclonedx15Json: Record<string, unknown> = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: generatedAt,
        tools: [
          {
            vendor: 'WinHood',
            name: 'WinHood SBOM Generator',
            version: '4.1.0',
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
      documentNamespace: `https://winhood.local/spdx/${software.id}/${crypto.randomUUID()}`,
      creationInfo: {
        created: generatedAt,
        creators: ['Tool: WinHood SBOM Generator-4.1.0'],
      },
      packages: components.map((c, idx) => ({
        SPDXID: `SPDXRef-Package-${idx + 1}`,
        name: c.name,
        versionInfo: c.version,
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
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

    return {
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
    };
  }

  public static extractComponents(filesMap: Record<string, string>): SbomComponentRecord[] {
    const components: SbomComponentRecord[] = [];
    const seen = new Set<string>();

    const addComponent = (rec: SbomComponentRecord) => {
      const key = `${rec.ecosystem}:${rec.name}@${rec.version}`;
      if (seen.has(key)) return;
      seen.add(key);
      components.push(rec);
    };

    // 1. package-lock.json (extracts both direct and transitive dependencies when present)
    const directNpmNames = new Set<string>();
    for (const [filePath, content] of Object.entries(filesMap)) {
      if (filePath.endsWith('package.json')) {
        try {
          const pkg = JSON.parse(content);
          const allDirect = {
            ...(pkg.dependencies || {}),
            ...(pkg.devDependencies || {}),
          };
          for (const [name, rawVer] of Object.entries(allDirect)) {
            directNpmNames.add(name);
            const ver = String(rawVer).replace(/^[\^~>=< ]+/, '') || '0.0.0';
            addComponent({
              bomRef: `pkg:npm/${name}@${ver}`,
              name,
              version: ver,
              purl: `pkg:npm/${name.replace('@', '%40')}@${ver}`,
              ecosystem: 'npm',
              license: 'UNKNOWN',
              dependencyScope: 'DIRECT',
              manifestFile: filePath,
            });
          }
        } catch {
          // Ignore malformed package.json
        }
      }
    }

    for (const [filePath, content] of Object.entries(filesMap)) {
      if (filePath.endsWith('package-lock.json')) {
        try {
          const lock = JSON.parse(content);
          if (lock.packages && typeof lock.packages === 'object') {
            for (const [pkgPath, meta] of Object.entries<any>(lock.packages)) {
              if (!pkgPath || pkgPath === '') continue;
              const name = pkgPath.replace(/^.*node_modules\//, '');
              const ver = String(meta?.version || '0.0.0');
              const license = typeof meta?.license === 'string' ? meta.license : 'UNKNOWN';
              const scope = directNpmNames.has(name) ? 'DIRECT' : 'TRANSITIVE';
              addComponent({
                bomRef: `pkg:npm/${name}@${ver}`,
                name,
                version: ver,
                purl: `pkg:npm/${name.replace('@', '%40')}@${ver}`,
                ecosystem: 'npm',
                license,
                dependencyScope: scope,
                manifestFile: filePath,
              });
            }
          }
        } catch {
          // Ignore malformed package-lock.json
        }
      }
    }

    // 2. Python requirements.txt & pyproject.toml
    for (const [filePath, content] of Object.entries(filesMap)) {
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
            });
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
          });
        }
      }
    }

    return components;
  }
}
