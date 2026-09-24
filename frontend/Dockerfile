# syntax=docker/dockerfile:1
#
# Stages: deps (dependencies) -> build (bundle) / test (vitest) -> serve (nginx).
# Node and the whole node_modules tree stay out of the published image.
#
# Nothing secret belongs here in any case: Vite inlines build-time values into
# the bundle, so anything passed in would be readable by every visitor.

# ---------------------------------------------------------------- deps -----
FROM node:22-alpine AS deps

WORKDIR /app

# From the lockfile, so the layer is cached and the install is reproducible.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# --------------------------------------------------------------- build -----
FROM deps AS build

COPY . .
RUN npm run build

# ---------------------------------------------------------------- test -----
# Component and unit tests (vitest + jsdom). They stub `fetch`, so this needs
# no backend, no database and no network. Branching from `deps` rather than
# `build` keeps the tests runnable even when the production bundle is broken —
# which is exactly when the tests are most worth reading.
FROM deps AS test

COPY . .
# Run unprivileged. /app must be owned by that user because Vite writes a
# transient config bundle next to vite.config.js when it loads the config.
RUN chown -R node:node /app
USER node
CMD ["npm", "run", "test"]

# --------------------------------------------------------------- serve -----
# The unprivileged nginx image runs as uid 101 and listens on 8080; the stock
# image would run its master process as root to bind port 80.
FROM nginxinc/nginx-unprivileged:1.27-alpine AS serve

# SPA routing + reverse proxy for /api/ (see nginx.conf).
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --quiet --spider http://127.0.0.1:8080/healthz || exit 1

CMD ["nginx", "-g", "daemon off;"]
