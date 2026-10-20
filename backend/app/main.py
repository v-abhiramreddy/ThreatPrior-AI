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

# CORS middleware configuration (avoids invalid wildcard + credentials combination)
def get_cors_origins() -> list[str]:
    raw = getattr(settings, "cors_allowed_origins", "").strip()
    if not raw:
        return ["http://localhost:5173", "http://127.0.0.1:5173"]
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


cors_origins = get_cors_origins()
is_wildcard = cors_origins == ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=not is_wildcard,
    allow_methods=["GET", "POST", "OPTIONS"],
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
    canonical_dist = dist_dir.resolve()
    index_file = canonical_dist / "index.html"
    logger.info(f"Serving production frontend build from {canonical_dist}")
    assets_dir = canonical_dist / "assets"
    if assets_dir.exists() and assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_root():
        return FileResponse(index_file)

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        # 1. Strict boundary: do not let unknown API routes fall through to HTML
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail=f"API endpoint '/{full_path}' not found")

        # 2. Immediate rejection of directory traversal, backslashes, null bytes, and path escapes
        if ".." in full_path or "\\" in full_path or "\x00" in full_path or full_path.startswith("/"):
            raise HTTPException(status_code=404, detail=f"File not found: '{full_path}'")

        # 3. Reject known system and backend paths from SPA fallback
        normalized_lower = full_path.lower().lstrip("/")
        if (
            normalized_lower.startswith(("etc/", "proc/", "sys/", "windows/", "winnt/", "backend/"))
            or normalized_lower in ("etc", "backend", "proc", "sys", "windows")
        ):
            raise HTTPException(status_code=404, detail=f"File not found: '{full_path}'")

        # 4. Canonical path resolution strictly contained within canonical_dist
        try:
            target_file = (canonical_dist / full_path).resolve()
        except (ValueError, RuntimeError):
            raise HTTPException(status_code=404, detail="Invalid path")

        if not target_file.is_relative_to(canonical_dist):
            raise HTTPException(status_code=404, detail="Access denied")

        # 5. Serve legitimate static file if it exists directly in dist (e.g. vite.svg, favicon)
        if target_file.is_file():
            return FileResponse(target_file)

        # 6. Reject requests that target specific file assets with extensions that do not exist
        if Path(full_path).suffix:
            raise HTTPException(status_code=404, detail=f"Static asset '/{full_path}' not found")

        # 7. Fallback to SPA index.html for legitimate client-side routing
        return FileResponse(index_file)
