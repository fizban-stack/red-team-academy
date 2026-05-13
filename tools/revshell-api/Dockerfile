# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first so the layer caches across code changes.
COPY requirements.txt .
RUN pip install -r requirements.txt

# Application code.
COPY core/ ./core/
COPY generators/ ./generators/
COPY routers/ ./routers/
COPY main.py ./

# Drop root.
RUN useradd --create-home --shell /bin/bash app && chown -R app:app /app
USER app

EXPOSE 8080

# Defaults — override at runtime with -e API_TOKEN=... -e AUDIT_LOG=... etc.
ENV HOST=0.0.0.0 PORT=8080 LOG_LEVEL=INFO

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health').read()" || exit 1

CMD ["python", "main.py"]
