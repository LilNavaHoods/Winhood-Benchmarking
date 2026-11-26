import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  const ngAllowedHosts = (process.env.NG_ALLOWED_HOSTS || '')
    .split(/[,\s]+/)
    .map((h) => h.trim())
    .filter(Boolean);
  const hostedPreviewAllowedHosts =
    ngAllowedHosts.length > 0 || Boolean(process.env.K_SERVICE)
      ? Array.from(new Set(['localhost', '127.0.0.1', '.run.app', ...ngAllowedHosts]))
      : undefined;

  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(import.meta.dirname, '.'),
      },
    },
    server: {
      ...(hostedPreviewAllowedHosts ? { allowedHosts: hostedPreviewAllowedHosts } : {}),
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
