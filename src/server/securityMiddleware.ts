import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type express from 'express';

export type DeploymentMode = 'LOCAL_DESKTOP' | 'LOCAL_WEB' | 'REMOTE_DEPLOYMENT';
export type RuntimeEnv = 'DOCKER_LOCAL_WEB' | 'ELECTRON_DESKTOP' | 'LOCAL_NODE';

export const MAX_TRACKED_IPS = 10_000;
export const DEFAULT_LOCKOUT_THRESHOLD = 5;
export const DEFAULT_LOCKOUT_DURATION_MS = 5 * 60_000;
export const DEFAULT_TRACKER_TTL_MS = 15 * 60_000;

const IPV4_OR_CIDR_REGEX =
  /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\/(?:3[0-2]|[12]?\d))?$/;

export function resolveTrustProxyConfig(
  rawValue?: string | number | boolean
): boolean | number | string | string[] {
  if (rawValue === undefined || rawValue === null) return false;
  if (typeof rawValue === 'boolean') return rawValue ? 1 : false;
  if (typeof rawValue === 'number') {
    return Number.isInteger(rawValue) && rawValue >= 1 && rawValue <= 10 ? rawValue : false;
  }
  const trimmed = String(rawValue).trim();
  if (!trimmed) return false;
  const lower = trimmed.toLowerCase();
  if (lower === 'false' || lower === '0' || lower === 'off' || lower === 'no') return false;
  if (lower === 'true') return 1;
  if (lower === 'loopback' || lower === 'linklocal' || lower === 'uniquelocal') return lower;
  if (/^\d+$/.test(trimmed)) {
    const hops = Number.parseInt(trimmed, 10);
    return hops >= 1 && hops <= 10 ? hops : false;
  }
  const parts = trimmed
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
  if (
    parts.length > 0 &&
    parts.every((p) => IPV4_OR_CIDR_REGEX.test(p) || p === '::1' || p === 'loopback')
  ) {
    return parts;
  }
  return false;
}

export function resolveDeploymentMode(options?: {
  deploymentMode?: DeploymentMode;
  environment?: string;
  host?: string;
}): DeploymentMode {
  const explicit = (options?.deploymentMode || process.env.WINHOOD_DEPLOYMENT_MODE || '')
    .trim()
    .toUpperCase();
  if (explicit === 'LOCAL_DESKTOP' || explicit === 'LOCAL_WEB' || explicit === 'REMOTE_DEPLOYMENT') {
    return explicit as DeploymentMode;
  }
  if (options?.environment === 'REMOTE_DEPLOYMENT') {
    return 'REMOTE_DEPLOYMENT';
  }
  if (
    options?.environment === 'ELECTRON_DESKTOP' ||
    options?.environment === 'WINDOWS_PACKAGED' ||
    process.env.WINHOOD_RUNTIME_ENV === 'ELECTRON_DESKTOP'
  ) {
    return 'LOCAL_DESKTOP';
  }
  const host = (options?.host || '').trim().toLowerCase();
  const isLoopback = !host || host === '127.0.0.1' || host === 'localhost' || host === '::1';
  if (!isLoopback && process.env.NODE_ENV === 'production') {
    return 'REMOTE_DEPLOYMENT';
  }
  return 'LOCAL_WEB';
}

export function resolveRuntimeEnv(options?: {
  environment?: string;
  runtimeEnv?: string;
  dockerEnvFileExists?: boolean;
}): RuntimeEnv {
  const explicit = (options?.runtimeEnv ?? process.env.WINHOOD_RUNTIME_ENV ?? '')
    .trim()
    .toUpperCase();
  if (explicit === 'DOCKER_LOCAL_WEB' || options?.environment === 'DOCKER_LOCAL_WEB') {
    return 'DOCKER_LOCAL_WEB';
  }
  if (
    explicit === 'ELECTRON_DESKTOP' ||
    options?.environment === 'ELECTRON_DESKTOP' ||
    options?.environment === 'WINDOWS_PACKAGED'
  ) {
    return 'ELECTRON_DESKTOP';
  }
  const hasDockerEnvFile =
    options?.dockerEnvFileExists !== undefined
      ? options.dockerEnvFileExists
      : fs.existsSync('/.dockerenv');
  if (hasDockerEnvFile) {
    return 'DOCKER_LOCAL_WEB';
  }
  return 'LOCAL_NODE';
}

export function parseValidPortNumber(raw?: string | number | null): number | null {
  if (raw === undefined || raw === null || raw === '') return null;
  const parsed = typeof raw === 'number' ? raw : Number.parseInt(String(raw).trim(), 10);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    return null;
  }
  return parsed;
}

export function buildAllowedOriginMap(options: {
  deploymentMode: DeploymentMode;
  effectivePort?: number;
  envPort?: string;
  winhoodPort?: string;
  allowedOriginsEnv?: string;
}): Map<string, string> {
  const map = new Map<string, string>();
  const addOrigin = (origin: string) => {
    const trimmed = origin.trim();
    if (trimmed) {
      map.set(trimmed, trimmed);
    }
  };

  addOrigin('http://localhost:3000');
  addOrigin('http://127.0.0.1:3000');

  if (options.deploymentMode === 'LOCAL_WEB') {
    const portCandidates = [
      parseValidPortNumber(options.effectivePort),
      parseValidPortNumber(options.envPort),
      parseValidPortNumber(options.winhoodPort),
    ];
    for (const port of portCandidates) {
      if (port !== null) {
        addOrigin(`http://localhost:${port}`);
        addOrigin(`http://127.0.0.1:${port}`);
      }
    }
  }

  for (const extra of (options.allowedOriginsEnv || '').split(',')) {
    addOrigin(extra);
  }
  return map;
}

export function constantTimeTokenMatch(provided: string, expected: string): boolean {
  if (!provided || !expected) return false;
  const a = crypto.createHash('sha256').update(provided, 'utf8').digest();
  const b = crypto.createHash('sha256').update(expected, 'utf8').digest();
  return crypto.timingSafeEqual(a, b);
}

export interface RateLimitOptions {
  windowMs: number;
  maxRequests: number;
  bucketName: string;
  maxTrackedKeys?: number;
}

export function createInMemoryRateLimiter(opts: RateLimitOptions): express.RequestHandler {
  const buckets = new Map<string, { count: number; resetAt: number }>();
  const maxTrackedKeys = opts.maxTrackedKeys ?? MAX_TRACKED_IPS;

  const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of buckets.entries()) {
      if (entry.resetAt <= now) {
        buckets.delete(key);
      }
    }
  }, Math.max(opts.windowMs, 15_000));
  cleanupTimer.unref();

  return (req, res, next) => {
    const now = Date.now();
    const actorReq = req as express.Request & { authUser?: { id?: string } };
    const actorKey =
      String(actorReq.authUser?.id || '') ||
      String(req.ip || req.socket?.remoteAddress || 'unknown');
    const compositeKey = `${opts.bucketName}:${actorKey}`;

    let entry = buckets.get(compositeKey);
    if (!entry || entry.resetAt <= now) {
      if (!entry && buckets.size >= maxTrackedKeys) {
        const oldestKey = buckets.keys().next().value;
        if (oldestKey !== undefined) {
          buckets.delete(oldestKey);
        }
      }
      entry = { count: 0, resetAt: now + opts.windowMs };
      buckets.set(compositeKey, entry);
    }

    entry.count += 1;
    const remaining = Math.max(0, opts.maxRequests - entry.count);
    const retryAfterSeconds = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));

    res.setHeader('X-RateLimit-Limit', String(opts.maxRequests));
    res.setHeader('X-RateLimit-Remaining', String(remaining));

    if (entry.count > opts.maxRequests) {
      res.setHeader('Retry-After', String(retryAfterSeconds));
      return res.status(429).json({
        error: 'RATE_LIMITED',
        bucket: opts.bucketName,
        retryAfterSeconds,
        message: `Limite de requisições excedido para ${opts.bucketName}. Tente novamente em ${retryAfterSeconds}s.`,
      });
    }
    return next();
  };
}

export interface RemoteAuthFailureEntry {
  count: number;
  lockedUntil: number;
  lastAttemptAt: number;
}

export interface RemoteAuthFailureTrackerOptions {
  maxTrackedIps?: number;
  lockoutThreshold?: number;
  lockoutDurationMs?: number;
  entryTtlMs?: number;
  cleanupIntervalMs?: number;
}

/**
 * Rastreador de falhas de autenticação remota com memória estritamente limitada
 * (evicção FIFO em MAX_TRACKED_IPS e limpeza periódica com timer `.unref()`).
 */
export class RemoteAuthFailureTracker {
  private readonly entries = new Map<string, RemoteAuthFailureEntry>();
  private readonly maxTrackedIps: number;
  private readonly lockoutThreshold: number;
  private readonly lockoutDurationMs: number;
  private readonly entryTtlMs: number;
  private readonly cleanupTimer: NodeJS.Timeout;

  constructor(options?: RemoteAuthFailureTrackerOptions) {
    this.maxTrackedIps = options?.maxTrackedIps ?? MAX_TRACKED_IPS;
    this.lockoutThreshold = options?.lockoutThreshold ?? DEFAULT_LOCKOUT_THRESHOLD;
    this.lockoutDurationMs = options?.lockoutDurationMs ?? DEFAULT_LOCKOUT_DURATION_MS;
    this.entryTtlMs = options?.entryTtlMs ?? DEFAULT_TRACKER_TTL_MS;

    const cleanupIntervalMs = options?.cleanupIntervalMs ?? 60_000;
    this.cleanupTimer = setInterval(() => {
      this.pruneExpired(Date.now());
    }, cleanupIntervalMs);
    this.cleanupTimer.unref();
  }

  public isLocked(ip: string, now = Date.now()): { locked: boolean; retryAfterSeconds: number } {
    const entry = this.entries.get(ip);
    if (!entry || entry.lockedUntil <= now) {
      return { locked: false, retryAfterSeconds: 0 };
    }
    return {
      locked: true,
      retryAfterSeconds: Math.max(1, Math.ceil((entry.lockedUntil - now) / 1000)),
    };
  }

  public recordFailure(
    ip: string,
    now = Date.now()
  ): { count: number; lockedUntil: number; locked: boolean } {
    const existing = this.entries.get(ip);
    const prevCount =
      existing && existing.lockedUntil <= now && now - existing.lastAttemptAt <= this.entryTtlMs
        ? existing.count
        : 0;
    const nextCount = prevCount + 1;
    const lockedUntil = nextCount >= this.lockoutThreshold ? now + this.lockoutDurationMs : 0;

    if (existing) {
      // Refresh LRU/insertion order
      this.entries.delete(ip);
    } else if (this.entries.size >= this.maxTrackedIps) {
      this.pruneExpired(now);
      while (this.entries.size >= this.maxTrackedIps) {
        const oldestIp = this.entries.keys().next().value;
        if (oldestIp === undefined) break;
        this.entries.delete(oldestIp);
      }
    }

    this.entries.set(ip, {
      count: nextCount,
      lockedUntil,
      lastAttemptAt: now,
    });

    return {
      count: nextCount,
      lockedUntil,
      locked: lockedUntil > now,
    };
  }

  public clear(ip: string): void {
    this.entries.delete(ip);
  }

  public pruneExpired(now = Date.now()): number {
    let removed = 0;
    for (const [ip, entry] of this.entries.entries()) {
      const lockExpired = entry.lockedUntil === 0 || entry.lockedUntil <= now;
      const stale = now - entry.lastAttemptAt > this.entryTtlMs;
      if (lockExpired && stale) {
        this.entries.delete(ip);
        removed += 1;
      }
    }
    return removed;
  }

  public size(): number {
    return this.entries.size;
  }

  public dispose(): void {
    clearInterval(this.cleanupTimer);
  }
}

export interface SecurityAuthAuditRecord {
  timestamp: string;
  action: 'REMOTE_AUTH_DENIED' | 'REMOTE_AUTH_LOCKED';
  method: string;
  path: string;
  origin: string;
  deploymentMode: DeploymentMode;
  failureReason: string;
  integrityState: string;
}

/**
 * Grava eventos de falha de autenticação em arquivo append-only `logs/security-auth-audit.jsonl`
 * sem acionar serialização síncrona completa do banco principal (mitiga DoS de I/O — WH-AUD-006).
 */
export function appendSecurityAuthAuditJsonl(
  dataDir: string,
  record: SecurityAuthAuditRecord
): string {
  const logsDir = path.join(dataDir, 'logs');
  const logFile = path.join(logsDir, 'security-auth-audit.jsonl');
  try {
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }
    fs.appendFileSync(logFile, `${JSON.stringify(record)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
    });
  } catch (err) {
    console.error('[WinHood Security Audit JSONL Error]:', err);
  }
  return logFile;
}
