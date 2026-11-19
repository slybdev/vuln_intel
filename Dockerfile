FROM oven/bun:1 AS frontend-build

WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

COPY index.html tsconfig.json vite.config.ts ./
COPY src ./src
RUN bun run build

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VULN_DATA_DIR=/data \
    VULN_FRONTEND_DIR=/app/dist

WORKDIR /app

COPY pyproject.toml README.md ./
COPY vuln_intel ./vuln_intel

RUN python -m pip install --no-cache-dir . \
    && mkdir -p /data \
    && chown 10001:10001 /data

COPY --from=frontend-build /app/dist ./dist

USER 10001:10001

EXPOSE 8000

CMD ["vuln-intel-dashboard", "--host", "0.0.0.0", "--port", "8000"]
