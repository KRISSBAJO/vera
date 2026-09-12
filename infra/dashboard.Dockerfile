# syntax=docker/dockerfile:1
#
# The review queue. Build from the repository root:
#   docker build -f infra/dashboard.Dockerfile -t vera-dashboard .

FROM node:22-bookworm-slim AS build
RUN corepack enable
WORKDIR /repo

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json ./
COPY apps/api/package.json apps/api/
COPY apps/dashboard/package.json apps/dashboard/
COPY packages packages
RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --filter @vera/dashboard...

COPY apps/dashboard apps/dashboard
# Telemetry is on by default in Next and would phone home from a design partner's network.
ENV NEXT_TELEMETRY_DISABLED=1
RUN pnpm --filter @vera/dashboard build

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=4100 HOSTNAME=0.0.0.0
WORKDIR /app

# The standalone output already contains the traced node_modules; static assets are separate.
COPY --from=build /repo/apps/dashboard/.next/standalone ./
COPY --from=build /repo/apps/dashboard/.next/static ./apps/dashboard/.next/static

USER node
EXPOSE 4100
CMD ["node", "apps/dashboard/server.js"]
