import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { defineConfig } from 'vite';

function extractExplicitHostname(rawValue: string | undefined): string | null {
  if (!rawValue) return null;
  const trimmed = rawValue.trim();
  if (!trimmed) return null;
  // Never allow bare wildcards or broad TLD suffixes such as ".run.app"
  if (trimmed === '*' || trimmed.startsWith('.')) return null;
  try {
    const parsed = trimmed.includes('://') ? new URL(trimmed) : new URL(`https://${trimmed}`);
    const hostname = parsed.hostname.toLowerCase();
    if (!hostname || hostname.startsWith('.') || hostname.includes('*')) return null;
    return hostname;
  } catch {
    return null;
  }
}

export function resolveViteAllowedHosts(env: Record<string, string | undefined>): string[] {
  const explicitHosts = new Set<string>(['localhost', '127.0.0.1']);

  const csvSources = [env.NG_ALLOWED_HOSTS, env.WINHOOD_ALLOWED_HOSTS];
  for (const src of csvSources) {
    if (!src) continue;
    for (const token of src.split(/[,\s]+/)) {
      const host = extractExplicitHostname(token);
      if (host) explicitHosts.add(host);
    }
  }

  const urlSources = [env.APP_URL, env.SHARED_APP_URL, env.DEV_APP_URL];
  for (const urlVal of urlSources) {
    const host = extractExplicitHostname(urlVal);
    if (host) explicitHosts.add(host);
  }

  return Array.from(explicitHosts);
}

export default defineConfig(() => {
  const allowedHosts = resolveViteAllowedHosts(process.env);

  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(import.meta.dirname, '.'),
      },
    },
    server: {
      allowedHosts,
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
