# syntax=docker/dockerfile:1
# Build context for this Dockerfile is the repo root (see infra/docker-compose.yml
# "frontend" service) -- not frontend/ alone -- because it also needs
# infra/docker/nginx.conf, which lives outside the frontend/ directory.

# --- Build stage ---
FROM node:22-slim AS build
WORKDIR /app
COPY frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY frontend/. .
RUN npm run build

# --- Serve stage: static files behind nginx, not the Vite dev server ---
FROM nginx:1.27-alpine AS serve

RUN addgroup -g 1000 sigmaforge && adduser -D -u 1000 -G sigmaforge sigmaforge

COPY --from=build /app/dist /usr/share/nginx/html
COPY infra/docker/nginx.conf /etc/nginx/conf.d/default.conf

RUN chown -R sigmaforge:sigmaforge /usr/share/nginx/html && \
    chmod -R a-w /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
