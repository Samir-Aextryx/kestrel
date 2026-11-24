FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:24-bookworm-slim
ENV NODE_ENV=production
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 git ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/server ./server
COPY --from=build /app/engines ./engines
COPY --from=build /app/plugins ./plugins
COPY --from=build /app/fixtures ./fixtures
COPY --from=build /app/scripts ./scripts
RUN mkdir -p /data && chown -R node:node /data /app
USER node
ENV KESTREL_DATA_DIR=/data
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD curl -fsS http://127.0.0.1:8787/api/health || exit 1
CMD ["node", "server/index.js"]
