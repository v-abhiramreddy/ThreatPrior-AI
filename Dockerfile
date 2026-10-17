# ==============================================================================
# ThreatPrior AI — Production Multi-Stage Dockerfile (Single Render Web Service)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Frontend Builder (Node.js 20)
# Compiles TypeScript and builds the production React Vite application to /app/dist
# ------------------------------------------------------------------------------
FROM node:20-alpine AS frontend-builder
WORKDIR /app

# Copy dependency manifests and install dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy frontend source and build configurations
COPY tsconfig.json tsconfig.app.json tsconfig.node.json vite.config.ts index.html ./
COPY public ./public
COPY src ./src

# Build production assets
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 2: Production Runtime (Python 3.12 slim)
# Serves the compiled React frontend and the FastAPI REST endpoints via Uvicorn
# ------------------------------------------------------------------------------
FROM python:3.12-slim AS runner

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

WORKDIR /app

# Install minimal system tools (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install backend Python dependencies
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy built frontend from Stage 1 into /app/dist
COPY --from=frontend-builder /app/dist ./dist

# Copy backend application source code
COPY backend/app ./backend/app

# Expose service port
EXPOSE 8000

# Health check against FastAPI /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# Start Uvicorn bound to 0.0.0.0:$PORT
CMD ["sh", "-c", "uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port ${PORT:-8000}"]
