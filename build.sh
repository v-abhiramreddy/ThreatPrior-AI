#!/usr/bin/env bash
# ==============================================================================
# ThreatPrior AI — Build Script for Single-Service Deployment
# ==============================================================================
set -e

echo "[ThreatPrior] Installing frontend dependencies..."
npm ci || npm install

echo "[ThreatPrior] Building React production bundle to dist/..."
npm run build

echo "[ThreatPrior] Installing backend Python dependencies..."
pip install -r backend/requirements.txt

echo "[ThreatPrior] Build complete. Ready for Uvicorn start."
