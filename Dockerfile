# --- build frontend static export ---
FROM node:20-alpine AS frontend
WORKDIR /app

COPY frontend/package*.json ./
RUN npm ci

COPY frontend ./
RUN npm run build
# Next export output is written to /app/out when output:'export'


# --- backend runtime ---
FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend ./backend

# Copy UI export into backend/static-ui
COPY --from=frontend /app/out ./backend/static-ui

ENV PYTHONPATH=/app/backend
ENV DEMO_MODE=1
ENV AUTH_MODE=oidc
ENV TESHT_SCHEME=http
ENV DATABASE_URL=sqlite:////tmp/tesht.db
ENV ENV=dev
ENV MIGRATIONS_STRICT=0

EXPOSE 8000

CMD ["sh", "-lc", "mkdir -p /data && cd backend && uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
