# syntax=docker/dockerfile:1.7
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY spray.py ./
COPY targets/ ./targets/

RUN useradd --create-home --shell /bin/bash spray && chown -R spray:spray /app
USER spray

ENTRYPOINT ["python", "spray.py"]
