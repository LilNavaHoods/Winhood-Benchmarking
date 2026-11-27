import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type { AuthorizedPerfTarget } from '../types/benchmark';

export type { AuthorizedPerfTarget };

export interface SsrfValidationResult {
  allowed: boolean;
  reason: string;
  parsedUrl?: URL;
  resolvedIps: string[];
  pinnedIp?: string;
}

// Standard cloud instance metadata link-local IPv4 address (RFC 3927 / AWS, GCP, Azure IMDS)
const CLOUD_METADATA_IPV4 = '169.254.169.254';

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
  CLOUD_METADATA_IPV4,
  'metadata.azure.internal',
]);

function ipv4OctetsToUint32(a: number, b: number, c: number, d: number): number {
  return (((a & 0xff) << 24) | ((b & 0xff) << 16) | ((c & 0xff) << 8) | (d & 0xff)) >>> 0;
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return -1;
  }
  return ipv4OctetsToUint32(parts[0]!, parts[1]!, parts[2]!, parts[3]!);
}

function inCidr4Octets(
  ip: string,
  baseOctets: readonly [number, number, number, number],
  maskBits: number
): boolean {
  const ipInt = ipv4ToInt(ip);
  if (ipInt < 0) return false;
  const baseInt = ipv4OctetsToUint32(baseOctets[0], baseOctets[1], baseOctets[2], baseOctets[3]);
  const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function hextetsToIpv4(hi: number, lo: number): string {
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

export function parseIpv6ToHextets(rawIp: string): number[] | null {
  const cleaned = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '').split('%')[0] ?? '';
  if (!cleaned || !cleaned.includes(':')) return null;

  let working = cleaned;
  // Convert trailing embedded dotted-quad IPv4 (e.g. ::ffff:127.0.0.1, 0:0:0:0:0:ffff:10.0.0.1, ::169.254.169.254)
  const lastColon = working.lastIndexOf(':');
  const tail = working.slice(lastColon + 1);
  if (tail.includes('.')) {
    if (!net.isIPv4(tail)) return null;
    const octets = tail.split('.').map((p) => Number.parseInt(p, 10));
    if (octets.length !== 4 || octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
      return null;
    }
    const hi = ((octets[0]! << 8) | octets[1]!).toString(16);
    const lo = ((octets[2]! << 8) | octets[3]!).toString(16);
    working = `${working.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const doubleColonParts = working.split('::');
  if (doubleColonParts.length > 2) return null;

  const parseGroups = (part: string): number[] | null => {
    if (!part) return [];
    const groups = part.split(':');
    const out: number[] = [];
    for (const g of groups) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(Number.parseInt(g, 16));
    }
    return out;
  };

  if (doubleColonParts.length === 2) {
    const left = parseGroups(doubleColonParts[0]!);
    const right = parseGroups(doubleColonParts[1]!);
    if (!left || !right) return null;
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    return [...left, ...new Array<number>(missing).fill(0), ...right];
  }

  const full = parseGroups(working);
  if (!full || full.length !== 8) return null;
  return full;
}

export function isDisallowedIpAddress(
  rawIp: string,
  allowLoopbackExplicit = false
): { blocked: boolean; reason?: string } {
  const ip = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!ip) return { blocked: true, reason: 'Endereço IP vazio.' };

  if (net.isIPv4(ip)) {
    if (inCidr4Octets(ip, [127, 0, 0, 0], 8)) {
      return allowLoopbackExplicit
        ? { blocked: false }
        : { blocked: true, reason: `Loopback IPv4 bloqueado (${ip}).` };
    }
    if (inCidr4Octets(ip, [10, 0, 0, 0], 8)) return { blocked: true, reason: `Rede privada RFC1918 bloqueada (${ip}).` };
    if (inCidr4Octets(ip, [172, 16, 0, 0], 12)) return { blocked: true, reason: `Rede privada RFC1918 bloqueada (${ip}).` };
    if (inCidr4Octets(ip, [192, 168, 0, 0], 16)) return { blocked: true, reason: `Rede privada RFC1918 bloqueada (${ip}).` };
    if (inCidr4Octets(ip, [169, 254, 0, 0], 16)) return { blocked: true, reason: `Link-local / Cloud Metadata bloqueado (${ip}).` };
    if (inCidr4Octets(ip, [0, 0, 0, 0], 8)) return { blocked: true, reason: `Endereço 0.0.0.0/8 bloqueado (${ip}).` };
    if (inCidr4Octets(ip, [100, 64, 0, 0], 10)) return { blocked: true, reason: `CGNAT RFC6598 bloqueado (${ip}).` };
    if (inCidr4Octets(ip, [224, 0, 0, 0], 4)) return { blocked: true, reason: `Multicast bloqueado (${ip}).` };
    if (inCidr4Octets(ip, [240, 0, 0, 0], 4)) return { blocked: true, reason: `Reservado/Broadcast bloqueado (${ip}).` };
    return { blocked: false };
  }

  if (ip.includes(':')) {
    const h = parseIpv6ToHextets(ip);
    if (!h) {
      return { blocked: true, reason: `Formato de IPv6 inválido ou malformado (${ip}).` };
    }

    const prefixZero0to3 = h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0;
    const prefixZero0to4 = prefixZero0to3 && h[4] === 0;
    const prefixZero0to5 = prefixZero0to4 && h[5] === 0;

    // Unspecified (::)
    if (prefixZero0to5 && h[6] === 0 && h[7] === 0) {
      return { blocked: true, reason: `Unspecified IPv6 bloqueado (${ip}).` };
    }

    // Loopback (::1 or 0:0:0:0:0:0:0:1)
    if (prefixZero0to5 && h[6] === 0 && h[7] === 1) {
      return allowLoopbackExplicit
        ? { blocked: false }
        : { blocked: true, reason: `Loopback IPv6 bloqueado (${ip}).` };
    }

    // IPv4-mapped IPv6 (::ffff:0:0/96, including expanded 0:0:0:0:0:ffff:...)
    if (prefixZero0to4 && h[5] === 0xffff) {
      const mappedV4 = hextetsToIpv4(h[6]!, h[7]!);
      return isDisallowedIpAddress(mappedV4, allowLoopbackExplicit);
    }

    // IPv4-translated IPv6 (::ffff:0:0:0/96, RFC 2765)
    if (prefixZero0to3 && h[4] === 0xffff && h[5] === 0) {
      const translatedV4 = hextetsToIpv4(h[6]!, h[7]!);
      return isDisallowedIpAddress(translatedV4, allowLoopbackExplicit);
    }

    // IPv4-compatible IPv6 (::/96, deprecated RFC 4291 — e.g., ::127.0.0.1, ::169.254.169.254, 0:0:0:0:0:0:7f00:1)
    if (prefixZero0to5) {
      const compatibleV4 = hextetsToIpv4(h[6]!, h[7]!);
      return isDisallowedIpAddress(compatibleV4, allowLoopbackExplicit);
    }

    // NAT64 Well-Known Prefix (64:ff9b::/96) and Local-Use (64:ff9b:1::/48)
    if (h[0] === 0x0064 && h[1] === 0xff9b) {
      return { blocked: true, reason: `NAT64 prefix bloqueado (${ip}).` };
    }

    // Link-local IPv6 (fe80::/10)
    if ((h[0]! & 0xffc0) === 0xfe80) {
      return { blocked: true, reason: `Link-local IPv6 bloqueado (${ip}).` };
    }

    // Unique-Local IPv6 (fc00::/7)
    if ((h[0]! & 0xfe00) === 0xfc00) {
      return { blocked: true, reason: `Unique-Local IPv6 (fc00::/7) bloqueado (${ip}).` };
    }

    // Multicast IPv6 (ff00::/8)
    if ((h[0]! & 0xff00) === 0xff00) {
      return { blocked: true, reason: `Multicast IPv6 bloqueado (${ip}).` };
    }

    // Documentation IPv6 (2001:db8::/32)
    if (h[0] === 0x2001 && h[1] === 0x0db8) {
      return { blocked: true, reason: `Documentação IPv6 (2001:db8::/32) bloqueado (${ip}).` };
    }

    return { blocked: false };
  }

  return { blocked: true, reason: `Formato de IP inválido ou desconhecido (${ip}).` };
}

export type DnsResolverFn = (hostname: string) => Promise<Array<{ address: string; family: number }>>;

const defaultDnsResolver: DnsResolverFn = async (hostname: string) => {
  return await dns.promises.lookup(hostname, { all: true, verbatim: true });
};

export interface PinnedSafeRequestOptions {
  targetUrl: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  authorizedTargets?: AuthorizedPerfTarget[];
  requireRegisteredTarget?: boolean;
  allowExplicitLoopback?: boolean;
  dnsResolver?: DnsResolverFn;
  timeoutMs?: number;
  maxRedirects?: number;
  followRedirects?: boolean;
  maxResponseBytes?: number;
}

export interface PinnedSafeResponse {
  ok: boolean;
  statusCode: number;
  latencyMs: number;
  finalUrl: string;
  headers: Record<string, string>;
  bodyText: string;
  json: <T = unknown>() => T;
}

export class SsrfGuard {
  public static isExplicitLoopbackUrl(rawUrl: string): boolean {
    try {
      const parsed = new URL(rawUrl);
      const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
      return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
    } catch {
      return false;
    }
  }

  public static async validateUrl(params: {
    targetUrl: string;
    authorizedTargets?: AuthorizedPerfTarget[];
    requireRegisteredTarget?: boolean;
    allowExplicitLoopback?: boolean;
    dnsResolver?: DnsResolverFn;
  }): Promise<SsrfValidationResult> {
    let parsed: URL;
    try {
      parsed = new URL(params.targetUrl);
    } catch {
      return { allowed: false, reason: 'URL malformada.', resolvedIps: [] };
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return {
        allowed: false,
        reason: `Protocolo proibido (${parsed.protocol}): apenas http/https autorizados.`,
        resolvedIps: [],
      };
    }

    if (parsed.username || parsed.password) {
      return {
        allowed: false,
        reason: 'Credenciais embutidas na URL não são permitidas.',
        resolvedIps: [],
      };
    }

    const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (!hostname) {
      return { allowed: false, reason: 'Hostname ausente.', resolvedIps: [] };
    }

    // Check explicit target registration
    if (params.requireRegisteredTarget) {
      const list = params.authorizedTargets || [];
      const match = list.find((t) => {
        try {
          return new URL(t.origin).origin === parsed.origin;
        } catch {
          return false;
        }
      });
      if (!match) {
        return {
          allowed: false,
          reason: `Destino não autorizado (${parsed.origin}): cadastre o ambiente previamente no registro de destinos autorizados.`,
          resolvedIps: [],
        };
      }
    }

    const allowLoopback = Boolean(params.allowExplicitLoopback);

    if (!allowLoopback && BLOCKED_HOSTNAMES.has(hostname)) {
      return {
        allowed: false,
        reason: `Hostname interno/metadata bloqueado por política SSRF (${hostname}).`,
        resolvedIps: [],
      };
    }

    // If literal IP, validate directly (including canonical IPv6 forms)
    if (net.isIP(hostname) !== 0 || hostname.includes(':')) {
      const check = isDisallowedIpAddress(hostname, allowLoopback);
      if (check.blocked) {
        return { allowed: false, reason: check.reason || 'IP bloqueado.', resolvedIps: [hostname] };
      }
      return {
        allowed: true,
        reason: 'IP literal validado.',
        parsedUrl: parsed,
        resolvedIps: [hostname],
        pinnedIp: hostname,
      };
    }

    // Resolve DNS and check ALL returned A/AAAA records
    const resolver = params.dnsResolver || defaultDnsResolver;
    let records: Array<{ address: string; family: number }>;
    try {
      records = await resolver(hostname);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'NXDOMAIN';
      return {
        allowed: false,
        reason: `Falha na resolução DNS para ${hostname}: ${msg}.`,
        resolvedIps: [],
      };
    }

    if (!records || records.length === 0) {
      return { allowed: false, reason: `Nenhum endereço IP retornado pelo DNS para ${hostname}.`, resolvedIps: [] };
    }

    const resolvedIps = records.map((r) => r.address);
    for (const rec of records) {
      const check = isDisallowedIpAddress(rec.address, allowLoopback);
      if (check.blocked) {
        return {
          allowed: false,
          reason: `DNS para ${hostname} resolveu para IP proibido (${rec.address}): ${check.reason}`,
          resolvedIps,
        };
      }
    }

    return {
      allowed: true,
      reason: 'Destino e resolução DNS validados.',
      parsedUrl: parsed,
      resolvedIps,
      pinnedIp: resolvedIps[0],
    };
  }

  /**
   * Executa requisição HTTP(S) com IP pinado (proteção contra DNS rebinding TOCTOU)
   * e revalidação de cada salto de redirecionamento HTTP (ou bloqueio estrito quando followRedirects=false).
   */
  public static async pinnedSafeRequest(
    params: PinnedSafeRequestOptions
  ): Promise<PinnedSafeResponse> {
    const followRedirects = params.followRedirects ?? true;
    const maxRedirects = followRedirects ? (params.maxRedirects ?? 3) : 0;
    const timeoutMs = params.timeoutMs ?? 4000;
    const maxResponseBytes = params.maxResponseBytes ?? 5 * 1024 * 1024;
    const initialOrigin = (() => {
      try {
        return new URL(params.targetUrl).origin;
      } catch {
        return '';
      }
    })();

    let currentUrl = params.targetUrl;
    let currentMethod = (params.method || 'GET').toUpperCase();
    let currentBody = params.body;

    for (let hop = 0; hop <= maxRedirects; hop++) {
      const validation = await SsrfGuard.validateUrl({
        targetUrl: currentUrl,
        authorizedTargets: params.authorizedTargets,
        requireRegisteredTarget: params.requireRegisteredTarget,
        allowExplicitLoopback: params.allowExplicitLoopback,
        dnsResolver: params.dnsResolver,
      });

      if (!validation.allowed || !validation.parsedUrl || !validation.pinnedIp) {
        throw new Error(`SSRF_BLOCKED: ${validation.reason}`);
      }

      const parsed = validation.parsedUrl;
      const pinnedIp = validation.pinnedIp;
      const family = net.isIPv6(pinnedIp) ? 6 : 4;
      const start = performance.now();

      const requestHeaders: Record<string, string> = {
        Host: parsed.host,
        'User-Agent': 'WinHood-Perf-Validator/4.4',
      };
      if (params.headers) {
        for (const [k, v] of Object.entries(params.headers)) {
          if (v === undefined) continue;
          // Strip sensitive credentials if following a cross-origin redirect
          if (hop > 0 && parsed.origin !== initialOrigin && k.toLowerCase() === 'authorization') {
            continue;
          }
          requestHeaders[k] = v;
        }
      }

      const bodyBuffer =
        currentBody === undefined
          ? undefined
          : Buffer.isBuffer(currentBody)
            ? currentBody
            : Buffer.from(currentBody, 'utf8');
      if (bodyBuffer && !Object.keys(requestHeaders).some((k) => k.toLowerCase() === 'content-length')) {
        requestHeaders['Content-Length'] = String(bodyBuffer.byteLength);
      }

      const resp = await new Promise<{
        statusCode: number;
        location?: string;
        headers: Record<string, string>;
        bodyText: string;
      }>((resolve, reject) => {
        const transport = parsed.protocol === 'https:' ? https : http;
        const cleanHost = parsed.hostname.replace(/^\[|\]$/g, '');
        const reqOptions: https.RequestOptions = {
          hostname: cleanHost,
          port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
          path: `${parsed.pathname}${parsed.search}`,
          method: currentMethod,
          timeout: timeoutMs,
          lookup: (_host, opts, cb) => {
            if (typeof opts === 'object' && opts !== null && opts.all) {
              (
                cb as unknown as (
                  err: NodeJS.ErrnoException | null,
                  addresses: dns.LookupAddress[]
                ) => void
              )(null, [{ address: pinnedIp, family }]);
            } else {
              cb(null, pinnedIp, family);
            }
          },
          headers: requestHeaders,
        };
        if (parsed.protocol === 'https:' && net.isIP(cleanHost) === 0) {
          reqOptions.servername = cleanHost;
        }

        const req = transport.request(reqOptions, (res) => {
          const loc = typeof res.headers.location === 'string' ? res.headers.location : undefined;
          const normalizedHeaders: Record<string, string> = {};
          for (const [hk, hv] of Object.entries(res.headers)) {
            if (typeof hv === 'string') {
              normalizedHeaders[hk.toLowerCase()] = hv;
            } else if (Array.isArray(hv)) {
              normalizedHeaders[hk.toLowerCase()] = hv.join(', ');
            }
          }
          const chunks: Buffer[] = [];
          let totalBytes = 0;
          let abortedForSize = false;

          res.on('data', (chunk: Buffer | string) => {
            if (abortedForSize) return;
            const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            totalBytes += buf.byteLength;
            if (totalBytes > maxResponseBytes) {
              abortedForSize = true;
              res.destroy();
              reject(new Error(`RESPONSE_TOO_LARGE: Resposta excedeu limite de ${maxResponseBytes} bytes.`));
              return;
            }
            chunks.push(buf);
          });
          res.on('end', () => {
            if (abortedForSize) return;
            resolve({
              statusCode: res.statusCode || 0,
              location: loc,
              headers: normalizedHeaders,
              bodyText: Buffer.concat(chunks).toString('utf8'),
            });
          });
          res.on('error', reject);
        });
        req.on('timeout', () => {
          req.destroy(new Error(`Timeout after ${timeoutMs}ms`));
        });
        req.on('error', reject);
        if (bodyBuffer) {
          req.write(bodyBuffer);
        }
        req.end();
      });

      const latencyMs = performance.now() - start;

      if (resp.statusCode >= 300 && resp.statusCode < 400) {
        if (!followRedirects || maxRedirects === 0) {
          throw new Error(
            `SSRF_REDIRECT_BLOCKED: Redirecionamento HTTP ${resp.statusCode} bloqueado.`
          );
        }
        if (resp.location) {
          if (hop >= maxRedirects) {
            throw new Error('SSRF_BLOCKED: Limite máximo de redirecionamentos excedido.');
          }
          currentUrl = new URL(resp.location, parsed.toString()).toString();
          if (resp.statusCode === 303 || ((resp.statusCode === 301 || resp.statusCode === 302) && currentMethod === 'POST')) {
            currentMethod = 'GET';
            currentBody = undefined;
          }
          continue;
        }
      }

      const bodyText = resp.bodyText;
      return {
        ok: resp.statusCode >= 200 && resp.statusCode < 300,
        statusCode: resp.statusCode,
        latencyMs,
        finalUrl: currentUrl,
        headers: resp.headers,
        bodyText,
        json: <T = unknown>() => JSON.parse(bodyText) as T,
      };
    }

    throw new Error('SSRF_BLOCKED: Redirecionamento inválido.');
  }
}
