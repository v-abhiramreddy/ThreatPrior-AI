import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import settings
from app.routers import health, vulnerabilities, triage
from app.services.cisa_client import cisa_client

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("threatprior.backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: preload CISA KEV catalog in background
    logger.info("Starting ThreatPrior AI backend service...")
    asyncio.create_task(cisa_client.ensure_catalog())
    yield
    # Shutdown
    logger.info("Shutting down ThreatPrior AI backend service...")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Vulnerability Intelligence Backend for ThreatPrior AI (NVD API 2.0, CISA KEV, EPSS)",
    lifespan=lifespan,
)

# CORS middleware for local development and cross-origin access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 1. API routers registered first so API endpoints always take precedence
app.include_router(health.router)
app.include_router(vulnerabilities.router)
app.include_router(triage.router)


# 2. Production Static SPA Serving (when frontend dist/ exists)
def get_dist_dir() -> Path:
    """Robustly resolve repository-root dist/ directory across dev and container environments."""
    repo_dist = Path(__file__).resolve().parent.parent.parent / "dist"
    if repo_dist.exists() and (repo_dist / "index.html").exists():
        return repo_dist
    backend_dist = Path(__file__).resolve().parent.parent / "dist"
    if backend_dist.exists() and (backend_dist / "index.html").exists():
        return backend_dist
    return repo_dist


dist_dir = get_dist_dir()
if dist_dir.exists() and (dist_dir / "index.html").exists():
    logger.info(f"Serving production frontend build from {dist_dir}")
    assets_dir = dist_dir / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_root():
        return FileResponse(dist_dir / "index.html")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        # Strict boundary: do not let unknown API routes fall through to HTML
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail=f"API endpoint '/{full_path}' not found")

        # Serve static file if it exists directly in dist (e.g. vite.svg, favicon)
        target_file = dist_dir / full_path
        if full_path and target_file.exists() and target_file.is_file():
            return FileResponse(target_file)

        # Fallback to SPA index.html for client-side routing
        return FileResponse(dist_dir / "index.html")

