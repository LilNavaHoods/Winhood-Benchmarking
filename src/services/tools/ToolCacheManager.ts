import fs from 'node:fs';
import path from 'node:path';
import { computeSha256 } from '../../engine/scoringEngine';

export interface ImmutableAnalysisCacheKeyInput {
  softwareId: string;
  commitHash: string;
  scannerType: string;
  scannerVersion: string;
  configHash: string;
  qualityProfileKey: string;
  rulesSignature: string;
  sonarVersion: string;
}

export interface CachedAnalysisEntry<T = unknown> {
  cacheKey: string;
  createdAt: string;
  lastAccessedAt: string;
  hitCount: number;
  inputMetadata: ImmutableAnalysisCacheKeyInput;
  payload: T;
}

/**
 * Gerenciador de Cache Inteligente (Seção 11.4 & 11.9)
 * O cache só pode ser reutilizado quando:
 * - O commit for igual
 * - A versão do scanner for igual
 * - A configuração for compatível
 * - O perfil de qualidade for igual
 * - As regras relevantes forem iguais
 * - A versão do SonarQube for compatível
 */
export class ToolCacheManager {
  private cacheDir: string;
  private indexFile: string;
  private memoryCache = new Map<string, CachedAnalysisEntry<any>>();

  constructor(baseDataDir: string) {
    this.cacheDir = path.join(baseDataDir, 'tool_cache');
    this.indexFile = path.join(this.cacheDir, 'immutable_analysis_cache.json');
    this.ensureCacheDir();
    this.loadFromDisk();
  }

  private ensureCacheDir(): void {
    if (!fs.existsSync(this.cacheDir)) {
      fs.mkdirSync(this.cacheDir, { recursive: true });
    }
  }

  private loadFromDisk(): void {
    try {
      if (fs.existsSync(this.indexFile)) {
        const raw = fs.readFileSync(this.indexFile, 'utf8');
        const entries = JSON.parse(raw) as CachedAnalysisEntry<any>[];
        for (const entry of entries) {
          this.memoryCache.set(entry.cacheKey, entry);
        }
      }
    } catch {
      this.memoryCache.clear();
    }
  }

  private persistToDisk(): void {
    try {
      this.ensureCacheDir();
      const entries = Array.from(this.memoryCache.values());
      fs.writeFileSync(this.indexFile, JSON.stringify(entries, null, 2), 'utf8');
    } catch {
      // Non-blocking cache persistence
    }
  }

  public static computeImmutableKey(input: ImmutableAnalysisCacheKeyInput): string {
    const canonical = [
      input.softwareId.trim(),
      input.commitHash.trim(),
      input.scannerType.trim(),
      input.scannerVersion.trim(),
      input.configHash.trim(),
      input.qualityProfileKey.trim(),
      input.rulesSignature.trim(),
      input.sonarVersion.trim(),
    ].join('|');
    return computeSha256(canonical);
  }

  public get<T>(input: ImmutableAnalysisCacheKeyInput): CachedAnalysisEntry<T> | null {
    const key = ToolCacheManager.computeImmutableKey(input);
    const found = this.memoryCache.get(key);
    if (!found) return null;

    // Validate all 6 strict conditions explicitly
    const meta = found.inputMetadata;
    if (
      meta.commitHash !== input.commitHash ||
      meta.scannerVersion !== input.scannerVersion ||
      meta.configHash !== input.configHash ||
      meta.qualityProfileKey !== input.qualityProfileKey ||
      meta.rulesSignature !== input.rulesSignature ||
      meta.sonarVersion !== input.sonarVersion
    ) {
      this.memoryCache.delete(key);
      return null;
    }

    found.hitCount += 1;
    found.lastAccessedAt = new Date().toISOString();
    return found as CachedAnalysisEntry<T>;
  }

  public set<T>(input: ImmutableAnalysisCacheKeyInput, payload: T): string {
    const key = ToolCacheManager.computeImmutableKey(input);
    const nowIso = new Date().toISOString();
    this.memoryCache.set(key, {
      cacheKey: key,
      createdAt: nowIso,
      lastAccessedAt: nowIso,
      hitCount: 0,
      inputMetadata: { ...input },
      payload,
    });
    this.persistToDisk();
    return key;
  }

  public invalidateForSoftware(softwareId: string): number {
    let removed = 0;
    for (const [k, v] of this.memoryCache.entries()) {
      if (v.inputMetadata.softwareId === softwareId) {
        this.memoryCache.delete(k);
        removed += 1;
      }
    }
    if (removed > 0) this.persistToDisk();
    return removed;
  }

  public clearExpiredTemporaryCache(maxAgeHours = 72): number {
    const cutoff = Date.now() - maxAgeHours * 3600 * 1000;
    let removed = 0;
    for (const [k, v] of this.memoryCache.entries()) {
      if (new Date(v.lastAccessedAt).getTime() < cutoff) {
        this.memoryCache.delete(k);
        removed += 1;
      }
    }
    if (removed > 0) this.persistToDisk();
    return removed;
  }

  public getCacheStats(): {
    entriesCount: number;
    totalHits: number;
    sizeKb: number;
  } {
    let totalHits = 0;
    for (const v of this.memoryCache.values()) {
      totalHits += v.hitCount;
    }
    let sizeKb = 0;
    try {
      if (fs.existsSync(this.indexFile)) {
        sizeKb = Math.round((fs.statSync(this.indexFile).size / 1024) * 10) / 10;
      }
    } catch {
      sizeKb = 0;
    }
    return {
      entriesCount: this.memoryCache.size,
      totalHits,
      sizeKb,
    };
  }
}
