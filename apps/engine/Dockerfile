# ── Stage 1: build / install dependencies ─────────────────────────────────────
FROM python:3.14-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.14-slim AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Non-root user
RUN addgroup --system app && adduser --system --ingroup app app

COPY --from=builder /install /usr/local
COPY . .

USER app

EXPOSE 8000

# - `&&` y no `;`: si las migraciones fallan el contenedor tiene que fallar, no arrancar contra un esquema viejo.
# - `exec`: uvicorn queda como proceso principal y recibe SIGTERM (cierre ordenado en cada despliegue).
# - --no-proxy-headers: la IP del cliente se decide en la aplicación (TRUSTED_PROXY_COUNT), no por una variable
#   del entorno que cambie quién es "el cliente" sin que el código lo sepa.
# - --no-server-header: no anunciar "uvicorn" en cada respuesta.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --no-proxy-headers --no-server-header"]
