# syntax=docker/dockerfile:1
#
# The VERA decision API. Build from the repository root:
#   docker build -f infra/api.Dockerfile -t vera-api .
#
# Two stages so the runtime image carries no compiler, no dev dependencies, and no source. What ships
# is dist/ plus production dependencies.

FROM node:22-bookworm-slim AS build
RUN corepack enable
WORKDIR /repo

# Dependency manifests first: this layer is cached until a package.json or the lockfile changes, so
# editing source does not re-resolve the whole workspace.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml turbo.json tsconfig.base.json ./
COPY apps/api/package.json apps/api/
COPY apps/dashboard/package.json apps/dashboard/
COPY packages packages
RUN --mount=type=cache,id=pnpm,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile --filter @vera/api...

COPY apps/api apps/api
RUN pnpm turbo run build --filter=@vera/api

# Prune to exactly what the API needs at runtime, with workspace links resolved into real files.
# --legacy: pnpm 10 otherwise requires inject-workspace-packages, which would change how the whole
# repo resolves dependencies during development just to satisfy a packaging step.
RUN pnpm deploy --legacy --filter=@vera/api --prod /app

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app /app

# node:22 ships an unprivileged `node` user. Running as root would mean a container escape starts as
# root on the host kernel namespace, for a process that only ever needs to read its own dist/.
USER node
EXPOSE 4000

# No shell, no init: node is PID 1 and receives SIGTERM directly, which server.ts handles.
CMD ["node", "dist/server.js"]
