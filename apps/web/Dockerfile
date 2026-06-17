# syntax=docker/dockerfile:1
# Build context is the repo root (see docker-compose.yml).

# ---- Stage 1: install + build ----
FROM node:20-alpine AS build
WORKDIR /app
# Workspace manifests first for better layer caching.
COPY package.json package-lock.json* ./
COPY packages/npm/web-components/package.json ./packages/npm/web-components/
COPY packages/npm/web-client/package.json ./packages/npm/web-client/
COPY apps/web/package.json ./apps/web/
RUN npm install
# Sources, then build the component package and the web app.
COPY packages/npm ./packages/npm
COPY apps/web ./apps/web
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build:packages && npm run build --workspace web

# ---- Stage 2: minimal runtime (Next.js standalone) ----
# Ships only the traced server + its production deps — no dev tooling, no npm
# cache, no source. Cuts the image from ~1.1 GB to a couple hundred MB.
FROM node:20-alpine AS final
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1
# standalone mirrors the monorepo layout (outputFileTracingRoot = repo root),
# so server.js lands at apps/web/server.js with a pruned node_modules at root.
COPY --from=build /app/apps/web/.next/standalone ./
COPY --from=build /app/apps/web/.next/static ./apps/web/.next/static
EXPOSE 3000
CMD ["node", "apps/web/server.js"]
