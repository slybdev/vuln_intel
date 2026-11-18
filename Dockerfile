FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VULN_DATA_DIR=/data

WORKDIR /app

COPY pyproject.toml README.md ./
COPY vuln_intel ./vuln_intel

RUN python -m pip install --no-cache-dir . \
    && mkdir -p /data \
    && chown 10001:10001 /data

USER 10001:10001

EXPOSE 8000

CMD ["vuln-intel-dashboard", "--host", "0.0.0.0", "--port", "8000"]
