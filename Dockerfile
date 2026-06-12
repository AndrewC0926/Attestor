# syntax=docker/dockerfile:1

# --- Build stage: install all deps, compile TypeScript, prune to prod deps ---
FROM node:22-bookworm AS builder
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json tsconfig.json ./
COPY packages ./packages
RUN npm ci
RUN npm run build
RUN npm prune --omit=dev

# --- Runtime stage: slim image with compiled output and production deps only ---
FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    ATTESTOR_POLICY_FILE=/app/policies/v0.yaml \
    ATTESTOR_CONTROLS_FILE=/app/data/iso42001-controls.json \
    ATTESTOR_KEY_FILE=/data/signing-key.json \
    ATTESTOR_BUFFER_FILE=/data/buffer.jsonl

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages ./packages
COPY --from=builder /app/package.json ./package.json
COPY policies ./policies
COPY data ./data

# Writable location for the signing key and offline buffer (persisted volume).
RUN mkdir -p /data && chown -R node:node /data
USER node

EXPOSE 8080
CMD ["node", "packages/gateway/dist/bin/gateway.js"]
