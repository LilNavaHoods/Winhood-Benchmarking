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

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data',
  '169.254.169.254',
  'metadata.azure.internal',
]);

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return -1;
  }
  return (((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0);
}

function inCidr4(ip: string, base: string, maskBits: number): boolean {
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt < 0 || baseInt < 0) return false;
  const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

export function isDisallowedIpAddress(rawIp: string, allowLoopbackExplicit = false): { blocked: boolean; reason?: string } {
  const ip = rawIp.trim().toLowerCase();
  if (!ip) return { blocked: true, reason: 'Endereço IP vazio.' };

  // Handle IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1 or ::ffff:7f00:1
  if (ip.startsWith('::ffff:')) {
    const suffix = ip.slice(7);
    if (net.isIPv4(suffix)) {
      return isDisallowedIpAddress(suffix, allowLoopbackExplicit);
    }
    const hexMatch = suffix.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hexMatch) {
      const hi = Number.parseInt(hexMatch[1]!, 16);
      const lo = Number.parseInt(hexMatch[2]!, 16);
      const v4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isDisallowedIpAddress(v4, allowLoopbackExplicit);
    }
    return { blocked: true, reason: `IPv6 mapeado bloqueado (${ip}).` };
  }

  if (net.isIPv4(ip)) {
    if (inCidr4(ip, '127.0.0.0', 8)) {
      return allowLoopbackExplicit ? { blocked: false } : { blocked: true, reason: `Loopback IPv4 bloqueado (${ip}).` };
    }
    if (inCidr4(ip, '10.0.0.0', 8)) return { blocked: true, reason: `Rede privada RFC1918 bloqueada (${ip}).` };
    if (inCidr4(ip, '172.16.0.0', 12)) return { blocked: true, reason: `Rede privada RFC1918 bloqueada (${ip}).` };
    if (inCidr4(ip, '192.168.0.0', 16)) return { blocked: true, reason: `Rede privada RFC1918 bloqueada (${ip}).` };
    if (inCidr4(ip, '169.254.0.0', 16)) return { blocked: true, reason: `Link-local / Cloud Metadata bloqueado (${ip}).` };
    if (inCidr4(ip, '0.0.0.0', 8)) return { blocked: true, reason: `Endereço 0.0.0.0/8 bloqueado (${ip}).` };
    if (inCidr4(ip, '100.64.0.0', 10)) return { blocked: true, reason: `CGNAT RFC6598 bloqueado (${ip}).` };
    if (inCidr4(ip, '224.0.0.0', 4)) return { blocked: true, reason: `Multicast bloqueado (${ip}).` };
    if (inCidr4(ip, '240.0.0.0', 4)) return { blocked: true, reason: `Reservado/Broadcast bloqueado (${ip}).` };
    return { blocked: false };
  }

  if (net.isIPv6(ip)) {
    const bare = ip.split('%')[0]!;
    if (bare === '::1' || bare === '0:0:0:0:0:0:0:1') {
      return allowLoopbackExplicit ? { blocked: false } : { blocked: true, reason: `Loopback IPv6 bloqueado (${ip}).` };
    }
    if (bare === '::' || bare === '0:0:0:0:0:0:0:0') {
      return { blocked: true, reason: `Unspecified IPv6 bloqueado (${ip}).` };
    }
    if (/^fe[89ab][0-9a-f]:/i.test(bare) || bare.startsWith('fe80')) {
      return { blocked: true, reason: `Link-local IPv6 bloqueado (${ip}).` };
    }
    if (/^f[cd][0-9a-f]{2}:/i.test(bare)) {
      return { blocked: true, reason: `Unique-Local IPv6 (fc00::/7) bloqueado (${ip}).` };
    }
    if (bare.startsWith('ff')) {
      return { blocked: true, reason: `Multicast IPv6 bloqueado (${ip}).` };
    }
    if (bare.startsWith('64:ff9b:')) {
      return { blocked: true, reason: `NAT64 prefix bloqueado (${ip}).` };
    }
    return { blocked: false };
  }

  return { blocked: true, reason: `Formato de IP inválido ou desconhecido (${ip}).` };
}

export type DnsResolverFn = (hostname: string) => Promise<Array<{ address: string; family: number }>>;

const defaultDnsResolver: DnsResolverFn = async (hostname: string) => {
  return await dns.promises.lookup(hostname, { all: true, verbatim: true });
};

export class SsrfGuard {
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

    // If literal IP, validate directly
    if (net.isIP(hostname) !== 0) {
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
    } catch (err: any) {
      return {
        allowed: false,
        reason: `Falha na resolução DNS para ${hostname}: ${err?.message || 'NXDOMAIN'}.`,
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
   * Executa requisição HTTP(S) com IP pinado (proteção contra DNS rebinding)
   * e revalidação de cada salto de redirecionamento HTTP (máximo 3 redirects).
   */
  public static async pinnedSafeRequest(params: {
    targetUrl: string;
    authorizedTargets?: AuthorizedPerfTarget[];
    requireRegisteredTarget?: boolean;
    allowExplicitLoopback?: boolean;
    dnsResolver?: DnsResolverFn;
    timeoutMs?: number;
    maxRedirects?: number;
  }): Promise<{ ok: boolean; statusCode: number; latencyMs: number; finalUrl: string }> {
    const maxRedirects = params.maxRedirects ?? 3;
    const timeoutMs = params.timeoutMs ?? 4000;
    let currentUrl = params.targetUrl;

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

      const resp = await new Promise<{ statusCode: number; location?: string }>((resolve, reject) => {
        const transport = parsed.protocol === 'https:' ? https : http;
        const req = transport.request(
          {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: `${parsed.pathname}${parsed.search}`,
            method: 'GET',
            timeout: timeoutMs,
            lookup: (_host, _opts, cb) => {
              cb(null, pinnedIp, family);
            },
            headers: {
              Host: parsed.host,
              'User-Agent': 'WinHood-Perf-Validator/4.2',
            },
          },
          (res) => {
            const loc = typeof res.headers.location === 'string' ? res.headers.location : undefined;
            res.on('data', () => {});
            res.on('end', () => resolve({ statusCode: res.statusCode || 0, location: loc }));
          }
        );
        req.on('timeout', () => {
          req.destroy(new Error(`Timeout after ${timeoutMs}ms`));
        });
        req.on('error', reject);
        req.end();
      });

      const latencyMs = performance.now() - start;

      if (resp.statusCode >= 300 && resp.statusCode < 400 && resp.location) {
        if (hop >= maxRedirects) {
          throw new Error('SSRF_BLOCKED: Limite máximo de redirecionamentos excedido.');
        }
        currentUrl = new URL(resp.location, parsed.toString()).toString();
        continue;
      }

      return {
        ok: resp.statusCode >= 200 && resp.statusCode < 300,
        statusCode: resp.statusCode,
        latencyMs,
        finalUrl: currentUrl,
      };
    }

    throw new Error('SSRF_BLOCKED: Redirecionamento inválido.');
  }
}
