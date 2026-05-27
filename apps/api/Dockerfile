# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app

RUN corepack enable && corepack prepare pnpm@9.4.0 --activate

# Copy workspace manifests first for layer-cached installs
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml* ./
COPY packages/core/package.json ./packages/core/
COPY packages/db/package.json   ./packages/db/
COPY apps/api/package.json       ./apps/api/

RUN pnpm install --frozen-lockfile

# Copy source and build
COPY tsconfig.base.json ./
COPY packages/core/ ./packages/core/
COPY packages/db/   ./packages/db/
COPY apps/api/      ./apps/api/

RUN pnpm --filter @recon/core build
RUN pnpm --filter @recon/db   build
RUN pnpm --filter @recon/api  build

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production

RUN corepack enable && corepack prepare pnpm@9.4.0 --activate

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml* ./
COPY packages/core/package.json ./packages/core/
COPY packages/db/package.json   ./packages/db/
COPY apps/api/package.json       ./apps/api/

RUN pnpm install --frozen-lockfile --prod

COPY --from=builder /app/packages/core/dist ./packages/core/dist
COPY --from=builder /app/packages/db/dist   ./packages/db/dist
COPY --from=builder /app/apps/api/dist      ./apps/api/dist

EXPOSE 3001
CMD ["node", "apps/api/dist/index.js"]
