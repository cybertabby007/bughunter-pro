# ── Stage 1: Build Next.js static export ─────────────────────────────────────
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Python runtime + static files ────────────────────────────────────
FROM python:3.11-slim
WORKDIR /app/backend

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./

# Copy Next.js static export into backend/static so FastAPI can serve it
COPY --from=frontend-builder /app/frontend/out ./static

EXPOSE 8000
CMD sh -c "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"
