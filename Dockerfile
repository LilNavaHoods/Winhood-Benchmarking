# syntax=docker/dockerfile:1.7

# ==============================================================================
# Stage 1 — Builder (compila frontend Vite dist/ e backend/worker ESM dist-server/)
# Versão de imagem base fixada explicitamente (sem tags mutáveis)
# ==============================================================================
FROM node:22.14.0-bookworm-slim AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

COPY index.html tsconfig.json vite.config.ts server.ts ./
COPY public ./public
COPY scripts ./scripts
COPY cli ./cli
COPY src ./src

RUN npm run check:browser-imports \
  && npm run build \
  && npm run build:server \
  && test -s dist/index.html \
  && test -s dist-server/server.mjs \
  && test -s dist-server/scanner-worker.mjs

# ==============================================================================
# Stage 2 — Production Dependencies (somente runtime, sem devDependencies)
# ==============================================================================
FROM node:22.14.0-bookworm-slim AS deps

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
  && npm cache clean --force

# ==============================================================================
# Stage 3 — Runtime Endurecido (não-root, Local-Web, volume criptografado /data/winhood)
# ==============================================================================
FROM node:22.14.0-bookworm-slim AS runtime

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --gid 1001 winhood \
  && useradd --uid 1001 --gid 1001 --create-home --shell /usr/sbin/nologin winhood \
  && mkdir -p /data/winhood/database /data/winhood/security /data/winhood/keys /data/winhood/reports /data/winhood/sonar /data/winhood/cache /data/winhood/logs /data/winhood/isolated_artifacts /data/winhood/tools /data/winhood/scanner_jobs /tmp/winhood-workspaces \
  && chown -R winhood:winhood /data/winhood /tmp/winhood-workspaces \
  && chmod 700 /data/winhood /tmp/winhood-workspaces

WORKDIR /app

COPY --from=deps --chown=winhood:winhood /app/node_modules ./node_modules
COPY --from=builder --chown=winhood:winhood /app/dist ./dist
COPY --from=builder --chown=winhood:winhood /app/dist-server ./dist-server
COPY --chown=winhood:winhood package.json LICENSE PRIVACY.md TERMS.md SECURITY.md ./

ENV NODE_ENV=production \
    PORT=3000 \
    WINHOOD_DEPLOYMENT_MODE=LOCAL_WEB \
    WINHOOD_RUNTIME_ENV=DOCKER_LOCAL_WEB \
    WINHOOD_ALLOW_NETWORK_BIND=true \
    WINHOOD_BIND_HOST=0.0.0.0 \
    WINHOOD_DATA_DIR=/data/winhood \
    WINHOOD_TEMP_WORKSPACE_DIR=/tmp/winhood-workspaces

USER winhood

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/api/health').then((r) => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "dist-server/server.mjs"]
